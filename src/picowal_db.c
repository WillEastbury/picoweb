/* picowal_db.c -- write-ahead-logged transactional key/value engine.
 *
 * On-disk model (see picowal_db.h for the full picture):
 *   <dir>/superblock.dat   A/B alternating checkpoint of directory state
 *   <dir>/base.dat         the checkpointed MAIN FILE (compacted snapshot)
 *   <dir>/wal-NNNNNNNN.wal WAL segments; highest id = "leading" (open)
 *
 * Every mutation is a record appended to the leading WAL segment. A
 * single put/delete is an implicit, immediately-committed transaction of
 * one record. Explicit transactions (picowal_db_txn_*) group several
 * records under one txn_id, with only the LAST record of a commit
 * carrying PICOWAL_REC_TXN_COMMIT -- recovery (scan_file_range, used both
 * at boot and for replica ingest) buffers a txn's records as it scans and
 * only applies them to the index once it sees that commit marker; an
 * incomplete trailing transaction (crash, or an explicit rollback that
 * simply never wrote a commit marker) is silently discarded and its
 * write_off is rolled back to the last successfully committed point, so
 * the abandoned bytes get overwritten by the next append.
 *
 * picowal_db_checkpoint() folds every SEALED WAL segment's live records
 * into a freshly rewritten base.dat and deletes those WAL files --
 * catching the main file up and truncating the log, the classic WAL
 * checkpoint cycle. The leading segment is never touched by a
 * checkpoint; it only becomes eligible once rotation seals it. */

#include "picowal_db.h"

#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PICOWAL_FILE_MAGIC   0x50574631u /* "PWF1": base.dat / wal-*.wal header */
#define PICOWAL_SUPER_MAGIC  0x50474157u /* "PWAL" */
#define PICOWAL_REC_MAGIC    0x574c5232u /* "WLR2" (bumped: header grew a txn_id field) */
#define PICOWAL_SB_VERSION   4u
#define PICOWAL_FILE_VERSION 1u
#define PICOWAL_SB_SLOTS     PICOWAL_SB_SLOT_COUNT

#define PICOWAL_REC_TOMBSTONE  0x01u
#define PICOWAL_REC_TXN_COMMIT 0x02u

#define PICOWAL_INDEX_BUCKETS 4096u
#define PICOWAL_TXN_MAX_OPS   4096u
#define PICOWAL_MAX_REPLICA_ACKS 32u

#define PICOWAL_SB_CHECKPOINT_INTERVAL 128u /* superblock checkpoint cadence, in appends */

#define PICOWAL_WAL_CHECK_INTERVAL_SEC   60u
#define PICOWAL_WAL_MIN_RECLAIMABLE_BYTES (8ULL * 1024ULL * 1024ULL)
#define PICOWAL_WAL_MIN_RECLAIMABLE_RATIO 0.4
#define PICOWAL_FLUSH_INTERVAL_MS 50

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t key;
    uint32_t len;
    uint32_t flags;
    uint64_t seq;
    uint64_t txn_id;
    uint64_t checksum;
} picowal_record_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t version;
    uint32_t seg_id;
    uint32_t generation;
    uint64_t checksum;
    uint8_t  reserved[488];
} picowal_file_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t sector_size;
    uint64_t segment_bytes;
    uint64_t generation;
    uint32_t base_generation;
    uint32_t leading_wal_id;
    uint64_t leading_write_off;
    uint64_t next_seq;
    uint64_t checksum;
    uint8_t  reserved[456];
} picowal_superblock_t;

_Static_assert(sizeof(picowal_file_hdr_t) == PICOWAL_SECTOR_BYTES, "file header must be one sector");
_Static_assert(sizeof(picowal_superblock_t) == PICOWAL_SECTOR_BYTES, "superblock slot must be one sector");

typedef struct picowal_index_entry {
    uint32_t key;
    uint32_t seg_id;
    uint64_t offset;
    uint32_t len;
    uint64_t seq;
    bool tombstone;
    struct picowal_index_entry* next;
} picowal_index_entry_t;

typedef struct picowal_wal_seg {
    uint32_t id;
    struct picowal_wal_seg* next;
} picowal_wal_seg_t; /* sealed WAL segments only; generation is always 1
                        (a WAL segment is only ever deleted whole, never
                        rewritten in place) */

typedef struct {
    char id[64];
    bool used;
    uint32_t seg_id;
    uint64_t offset;
} picowal_ack_slot_t;

struct picowal_db {
    char dir_path[768];
    uint64_t segment_bytes;

    int base_fd;
    uint32_t base_generation;
    uint64_t base_bytes; /* valid content bytes, excludes header sector */

    int leading_fd;
    uint32_t leading_wal_id;
    uint64_t leading_write_off;
    picowal_wal_seg_t* sealed_wals; /* ascending by id */

    uint64_t next_seq;
    uint64_t sb_generation;
    uint32_t appends_since_checkpoint;

    bool read_only;
    bool bg_started;
    volatile bool dirty_unsynced;
    volatile uint64_t schema_gen; /* bumped on every write to pack 1 (name
                                      registry) or pack 2 (schema store) so
                                      picowal_query.c's parsed-query cache
                                      can detect staleness cheaply */

    pthread_mutex_t mu;
    picowal_index_entry_t* buckets[PICOWAL_INDEX_BUCKETS];

    pthread_mutex_t ack_mu;
    pthread_cond_t ack_cv;
    picowal_ack_slot_t acks[PICOWAL_MAX_REPLICA_ACKS];
    uint32_t ack_quorum;
};

struct picowal_txn {
    picowal_db_t* db;
    uint64_t txn_id; /* 0 until the first op assigns it */
    uint32_t seg_id;
    struct {
        uint32_t key;
        uint32_t seg_id;
        uint64_t offset;
        uint32_t len;
        uint64_t seq;
        bool tombstone;
    } ops[PICOWAL_TXN_MAX_OPS];
    uint32_t op_count;
    uint64_t last_hdr_offset;
};

/* ============================================================ helpers */

static size_t bucket_idx(uint32_t key) {
    return (size_t)(metal_fnv1a(&key, sizeof(key)) & (PICOWAL_INDEX_BUCKETS - 1));
}

static uint64_t align_up_512(uint64_t n) {
    return (n + (PICOWAL_SECTOR_BYTES - 1ULL)) & ~(PICOWAL_SECTOR_BYTES - 1ULL);
}

static int pread_full(int fd, void* out, size_t len, uint64_t off) {
    size_t got = 0;
    while (got < len) {
        ssize_t r = pread(fd, (uint8_t*)out + got, len - got, (off_t)(off + got));
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int pwrite_full(int fd, const void* in, size_t len, uint64_t off) {
    size_t wrote = 0;
    while (wrote < len) {
        ssize_t w = pwrite(fd, (const uint8_t*)in + wrote, len - wrote, (off_t)(off + wrote));
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        wrote += (size_t)w;
    }
    return 0;
}

static bool is_zeroed(const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    for (size_t i = 0; i < n; i++) if (b[i] != 0) return false;
    return true;
}

static uint64_t rec_checksum(uint32_t key, uint32_t len, uint32_t flags,
                             uint64_t seq, uint64_t txn_id, const uint8_t* payload) {
    uint64_t h = metal_fnv1a_init();
    h = metal_fnv1a_step(h, &key, sizeof(key));
    h = metal_fnv1a_step(h, &len, sizeof(len));
    h = metal_fnv1a_step(h, &flags, sizeof(flags));
    h = metal_fnv1a_step(h, &seq, sizeof(seq));
    h = metal_fnv1a_step(h, &txn_id, sizeof(txn_id));
    if (payload && len) h = metal_fnv1a_step(h, payload, len);
    return h;
}

static uint64_t file_hdr_checksum(const picowal_file_hdr_t* h) {
    uint64_t v = metal_fnv1a_init();
    v = metal_fnv1a_step(v, &h->magic, sizeof(h->magic));
    v = metal_fnv1a_step(v, &h->version, sizeof(h->version));
    v = metal_fnv1a_step(v, &h->seg_id, sizeof(h->seg_id));
    v = metal_fnv1a_step(v, &h->generation, sizeof(h->generation));
    return v;
}

static bool file_hdr_valid(const picowal_file_hdr_t* h, uint32_t want_seg_id) {
    return h->magic == PICOWAL_FILE_MAGIC && h->version == PICOWAL_FILE_VERSION &&
           h->seg_id == want_seg_id && file_hdr_checksum(h) == h->checksum;
}

static uint64_t sb_checksum(const picowal_superblock_t* sb) {
    uint64_t h = metal_fnv1a_init();
    h = metal_fnv1a_step(h, &sb->magic, sizeof(sb->magic));
    h = metal_fnv1a_step(h, &sb->version, sizeof(sb->version));
    h = metal_fnv1a_step(h, &sb->sector_size, sizeof(sb->sector_size));
    h = metal_fnv1a_step(h, &sb->segment_bytes, sizeof(sb->segment_bytes));
    h = metal_fnv1a_step(h, &sb->generation, sizeof(sb->generation));
    h = metal_fnv1a_step(h, &sb->base_generation, sizeof(sb->base_generation));
    h = metal_fnv1a_step(h, &sb->leading_wal_id, sizeof(sb->leading_wal_id));
    h = metal_fnv1a_step(h, &sb->leading_write_off, sizeof(sb->leading_write_off));
    h = metal_fnv1a_step(h, &sb->next_seq, sizeof(sb->next_seq));
    return h;
}

static bool sb_slot_valid(const picowal_superblock_t* sb) {
    return sb->magic == PICOWAL_SUPER_MAGIC && sb->version == PICOWAL_SB_VERSION &&
           sb->sector_size == PICOWAL_SECTOR_BYTES && sb->leading_wal_id >= 1 &&
           sb->next_seq >= 1 && sb_checksum(sb) == sb->checksum;
}

static void path_join(char* out, size_t out_cap, const char* dir, const char* name) {
    snprintf(out, out_cap, "%s/%s", dir, name);
}

static void sb_path(picowal_db_t* db, char* out, size_t out_cap) {
    path_join(out, out_cap, db->dir_path, "superblock.dat");
}

static void base_path(picowal_db_t* db, char* out, size_t out_cap) {
    path_join(out, out_cap, db->dir_path, "base.dat");
}

static void wal_path(picowal_db_t* db, uint32_t id, char* out, size_t out_cap) {
    char name[32];
    snprintf(name, sizeof(name), "wal-%08u.wal", id);
    path_join(out, out_cap, db->dir_path, name);
}

/* ============================================================ index */

static void clear_index(picowal_db_t* db) {
    for (size_t i = 0; i < PICOWAL_INDEX_BUCKETS; i++) {
        picowal_index_entry_t* e = db->buckets[i];
        while (e) { picowal_index_entry_t* n = e->next; free(e); e = n; }
        db->buckets[i] = NULL;
    }
}

static picowal_index_entry_t* index_find(picowal_db_t* db, uint32_t key) {
    for (picowal_index_entry_t* e = db->buckets[bucket_idx(key)]; e; e = e->next)
        if (e->key == key) return e;
    return NULL;
}

static int index_upsert(picowal_db_t* db, uint32_t key, uint32_t seg_id, uint64_t off,
                        uint32_t len, uint64_t seq, bool tombstone) {
    size_t bi = bucket_idx(key);
    for (picowal_index_entry_t* e = db->buckets[bi]; e; e = e->next) {
        if (e->key == key) {
            if (seq >= e->seq) {
                e->seg_id = seg_id; e->offset = off; e->len = len;
                e->seq = seq; e->tombstone = tombstone;
            }
            return 0;
        }
    }
    picowal_index_entry_t* e = (picowal_index_entry_t*)calloc(1, sizeof(*e));
    if (!e) return -1;
    e->key = key; e->seg_id = seg_id; e->offset = off; e->len = len;
    e->seq = seq; e->tombstone = tombstone;
    e->next = db->buckets[bi];
    db->buckets[bi] = e;
    return 0;
}

/* Drops every index entry currently pointing at seg_id (used by replica
 * install/drop of a segment before re-indexing its replacement). */
static void index_drop_segment(picowal_db_t* db, uint32_t seg_id) {
    for (size_t bi = 0; bi < PICOWAL_INDEX_BUCKETS; bi++) {
        picowal_index_entry_t** pp = &db->buckets[bi];
        while (*pp) {
            if ((*pp)->seg_id == seg_id) {
                picowal_index_entry_t* dead = *pp;
                *pp = dead->next;
                free(dead);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
}

/* ============================================================ segment fd resolution */

/* Resolves a readable fd for seg_id. For base/leading this borrows the
 * long-lived fd (caller must NOT close it); for a sealed WAL segment it
 * opens a fresh read-only fd (caller must close it iff *out_should_close). */
static int resolve_read_fd(picowal_db_t* db, uint32_t seg_id, bool* out_should_close) {
    *out_should_close = false;
    if (seg_id == PICOWAL_BASE_SEG_ID) return db->base_fd;
    if (seg_id == db->leading_wal_id) return db->leading_fd;
    char path[800];
    wal_path(db, seg_id, path, sizeof(path));
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) *out_should_close = true;
    return fd;
}

/* ============================================================ superblock */

static bool write_superblock_locked(picowal_db_t* db) {
    char path[800];
    sb_path(db, path, sizeof(path));
    int fd = open(path, O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) return false;

    uint64_t generation = db->sb_generation + 1;
    uint64_t slot = generation % PICOWAL_SB_SLOTS;

    picowal_superblock_t sb;
    memset(&sb, 0, sizeof(sb));
    sb.magic = PICOWAL_SUPER_MAGIC;
    sb.version = PICOWAL_SB_VERSION;
    sb.sector_size = PICOWAL_SECTOR_BYTES;
    sb.segment_bytes = db->segment_bytes;
    sb.generation = generation;
    sb.base_generation = db->base_generation;
    sb.leading_wal_id = db->leading_wal_id;
    sb.leading_write_off = db->leading_write_off;
    sb.next_seq = db->next_seq;
    sb.checksum = sb_checksum(&sb);

    bool ok = pwrite_full(fd, &sb, sizeof(sb), slot * PICOWAL_SECTOR_BYTES) == 0 &&
              fdatasync(fd) == 0;
    close(fd);
    if (!ok) return false;
    db->sb_generation = generation;
    db->appends_since_checkpoint = 0;
    return true;
}

/* ============================================================ scan / recovery */

/* Scans records in [start_off, stop_off) of one file (base.dat or a
 * single wal-*.wal), buffering an in-flight transaction's records until
 * its commit-marked record is seen (then upserting all of them into the
 * index), or discarding them if the scan ends first (crash/rollback).
 * *out_end is the offset right after the last successfully COMMITTED
 * record (i.e. rolled back past any dangling uncommitted tail) -- for the
 * leading WAL segment that becomes the new write_off, so the next append
 * overwrites any abandoned bytes. Returns false only on hard I/O/OOM
 * error. */
static bool scan_file_range(picowal_db_t* db, int fd, uint32_t seg_id,
                            uint64_t start_off, uint64_t stop_off,
                            uint64_t* out_end, uint64_t* out_max_seq) {
    uint64_t off = start_off;
    uint64_t last_committed_end = start_off;
    uint64_t max_seq = 0;
    uint8_t payload[PICOWAL_DATA_MAX];

    typedef struct { uint32_t key; uint64_t offset; uint32_t len; uint64_t seq; bool tombstone; } pend_t;
    pend_t* pending = (pend_t*)malloc(sizeof(pend_t) * PICOWAL_TXN_MAX_OPS);
    uint32_t pending_n = 0;
    uint64_t pending_txn_id = 0;
    if (!pending) { errno = ENOMEM; return false; }

    while (off + sizeof(picowal_record_hdr_t) <= stop_off) {
        picowal_record_hdr_t h;
        if (pread_full(fd, &h, sizeof(h), off) != 0) break;
        if (is_zeroed(&h, sizeof(h))) break;
        if (h.magic != PICOWAL_REC_MAGIC) break;
        if (h.len > PICOWAL_DATA_MAX) break;
        if ((h.flags & ~(PICOWAL_REC_TOMBSTONE | PICOWAL_REC_TXN_COMMIT)) != 0) break;

        uint64_t span = align_up_512(sizeof(h) + h.len);
        if (off + span > stop_off) break;

        if (h.len > 0) {
            if (pread_full(fd, payload, h.len, off + sizeof(h)) != 0) break;
        }
        uint64_t chk = rec_checksum(h.key, h.len, h.flags, h.seq, h.txn_id, h.len ? payload : NULL);
        if (chk != h.checksum) break;

        if (pending_n > 0 && h.txn_id != pending_txn_id) {
            /* A different txn_id appeared before the previous one
             * committed -- the previous transaction was abandoned. */
            pending_n = 0;
        }
        pending_txn_id = h.txn_id;
        if (pending_n < PICOWAL_TXN_MAX_OPS) {
            pending[pending_n].key = h.key;
            pending[pending_n].offset = off;
            pending[pending_n].len = h.len;
            pending[pending_n].seq = h.seq;
            pending[pending_n].tombstone = (h.flags & PICOWAL_REC_TOMBSTONE) != 0;
            pending_n++;
        }
        if (h.seq > max_seq) max_seq = h.seq;
        off += span;

        if (h.flags & PICOWAL_REC_TXN_COMMIT) {
            for (uint32_t i = 0; i < pending_n; i++) {
                if (index_upsert(db, pending[i].key, seg_id, pending[i].offset,
                                 pending[i].len, pending[i].seq, pending[i].tombstone) != 0) {
                    free(pending);
                    errno = ENOMEM;
                    return false;
                }
                uint16_t card = 0; uint32_t recid = 0;
                picowal_db_unpack_key(pending[i].key, &card, &recid);
                if (card == 1 || card == 2) db->schema_gen++;
            }
            pending_n = 0;
            last_committed_end = off;
        }
    }

    free(pending);
    *out_end = last_committed_end;
    *out_max_seq = max_seq;
    return true;
}

static bool scan_volume(picowal_db_t* db) {
    clear_index(db);
    uint64_t end = 0, max_seq = 0, overall_max_seq = 0;

    if (db->base_bytes > 0 || db->base_fd >= 0) {
        struct stat st;
        if (fstat(db->base_fd, &st) == 0 && (uint64_t)st.st_size > PICOWAL_SEG_DATA_START) {
            if (!scan_file_range(db, db->base_fd, PICOWAL_BASE_SEG_ID,
                                 PICOWAL_SEG_DATA_START, (uint64_t)st.st_size, &end, &max_seq))
                return false;
            if (max_seq > overall_max_seq) overall_max_seq = max_seq;
        }
    }

    for (picowal_wal_seg_t* s = db->sealed_wals; s; s = s->next) {
        char path[800];
        wal_path(db, s->id, path, sizeof(path));
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue; /* tolerate a segment vanishing mid-scan */
        struct stat st;
        if (fstat(fd, &st) == 0 && (uint64_t)st.st_size > PICOWAL_SEG_DATA_START) {
            if (!scan_file_range(db, fd, s->id, PICOWAL_SEG_DATA_START,
                                 (uint64_t)st.st_size, &end, &max_seq)) {
                close(fd);
                return false;
            }
            if (max_seq > overall_max_seq) overall_max_seq = max_seq;
        }
        close(fd);
    }

    struct stat lst;
    uint64_t leading_stop = PICOWAL_SEG_DATA_START;
    if (fstat(db->leading_fd, &lst) == 0) leading_stop = (uint64_t)lst.st_size;
    if (!scan_file_range(db, db->leading_fd, db->leading_wal_id, PICOWAL_SEG_DATA_START,
                         leading_stop, &end, &max_seq))
        return false;
    if (max_seq > overall_max_seq) overall_max_seq = max_seq;

    db->leading_write_off = end;
    if (overall_max_seq + 1 > db->next_seq) db->next_seq = overall_max_seq + 1;
    return true;
}

/* ============================================================ open / format */

static void free_sealed_list(picowal_db_t* db) {
    picowal_wal_seg_t* s = db->sealed_wals;
    while (s) { picowal_wal_seg_t* n = s->next; free(s); s = n; }
    db->sealed_wals = NULL;
}

static int seg_id_cmp(const void* a, const void* b) {
    uint32_t ia = *(const uint32_t*)a, ib = *(const uint32_t*)b;
    return (ia > ib) - (ia < ib);
}

/* Discovers wal-NNNNNNNN.wal files on disk. Returns the count found and
 * fills *out_ids (caller-allocated, capacity max_ids) ascending. */
static uint32_t discover_wal_ids(const char* dir, uint32_t* out_ids, uint32_t max_ids) {
    DIR* d = opendir(dir);
    if (!d) return 0;
    uint32_t n = 0;
    struct dirent* ent;
    while ((ent = readdir(d)) != NULL) {
        uint32_t id = 0;
        if (sscanf(ent->d_name, "wal-%8u.wal", &id) == 1 && n < max_ids) {
            out_ids[n++] = id;
        }
    }
    closedir(d);
    qsort(out_ids, n, sizeof(uint32_t), seg_id_cmp);
    return n;
}

static bool write_file_header(int fd, uint32_t seg_id, uint32_t generation) {
    picowal_file_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.magic = PICOWAL_FILE_MAGIC;
    h.version = PICOWAL_FILE_VERSION;
    h.seg_id = seg_id;
    h.generation = generation;
    h.checksum = file_hdr_checksum(&h);
    return pwrite_full(fd, &h, sizeof(h), 0) == 0;
}

static bool load_or_format(picowal_db_t* db, const char* dir_path,
                          uint64_t want_segment_bytes, bool format) {
    struct stat dst;
    bool dir_exists = (stat(dir_path, &dst) == 0 && S_ISDIR(dst.st_mode));
    if (!dir_exists) {
        if (!format) { errno = ENOENT; return false; }
        if (mkdir(dir_path, 0700) != 0 && errno != EEXIST) return false;
    }

    if (want_segment_bytes == 0) want_segment_bytes = PICOWAL_DEFAULT_SEGMENT_BYTES;
    if ((want_segment_bytes % PICOWAL_SECTOR_BYTES) != 0) { errno = EINVAL; return false; }

    size_t plen = strlen(dir_path);
    if (plen >= sizeof(db->dir_path)) { errno = ENAMETOOLONG; return false; }
    memcpy(db->dir_path, dir_path, plen + 1);

    char sbp[800];
    sb_path(db, sbp, sizeof(sbp));
    bool sb_existed = (access(sbp, F_OK) == 0);

    int sbfd = open(sbp, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (sbfd < 0) return false;

    picowal_superblock_t sb0, sb1;
    memset(&sb0, 0, sizeof(sb0));
    memset(&sb1, 0, sizeof(sb1));
    bool have0 = sb_existed && pread_full(sbfd, &sb0, sizeof(sb0), 0) == 0 && sb_slot_valid(&sb0);
    bool have1 = sb_existed && pread_full(sbfd, &sb1, sizeof(sb1), PICOWAL_SECTOR_BYTES) == 0 && sb_slot_valid(&sb1);
    bool have_sb = have0 || have1;
    picowal_superblock_t* winner = NULL;
    if (have0 && have1) winner = (sb0.generation >= sb1.generation) ? &sb0 : &sb1;
    else if (have0) winner = &sb0;
    else if (have1) winner = &sb1;

    bool should_format = format && !have_sb;
    if (!have_sb && !format) { close(sbfd); errno = EINVAL; return false; }
    if (have_sb && want_segment_bytes != 0 && winner->segment_bytes != want_segment_bytes) {
        /* Caller asked for a specific cap that disagrees with what's on
         * disk -- keep the on-disk value (segment_bytes only matters for
         * new rotations) rather than failing outright. */
        want_segment_bytes = winner->segment_bytes;
    }

    char bp[800];
    base_path(db, bp, sizeof(bp));

    if (should_format) {
        int bfd = open(bp, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (bfd < 0) { close(sbfd); return false; }
        if (!write_file_header(bfd, PICOWAL_BASE_SEG_ID, 1) || fdatasync(bfd) != 0) {
            close(bfd); close(sbfd); return false;
        }
        close(bfd);

        char wp[800];
        wal_path(db, 1, wp, sizeof(wp));
        int wfd = open(wp, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (wfd < 0) { close(sbfd); return false; }
        if (!write_file_header(wfd, 1, 1) || fdatasync(wfd) != 0) {
            close(wfd); close(sbfd); return false;
        }
        close(wfd);

        picowal_superblock_t sb;
        memset(&sb, 0, sizeof(sb));
        sb.magic = PICOWAL_SUPER_MAGIC;
        sb.version = PICOWAL_SB_VERSION;
        sb.sector_size = PICOWAL_SECTOR_BYTES;
        sb.segment_bytes = want_segment_bytes;
        sb.generation = 1;
        sb.base_generation = 1;
        sb.leading_wal_id = 1;
        sb.leading_write_off = PICOWAL_SEG_DATA_START;
        sb.next_seq = 1;
        sb.checksum = sb_checksum(&sb);
        bool ok = pwrite_full(sbfd, &sb, sizeof(sb), 0) == 0 &&
                  pwrite_full(sbfd, &sb, sizeof(sb), PICOWAL_SECTOR_BYTES) == 0 &&
                  fdatasync(sbfd) == 0;
        close(sbfd);
        if (!ok) return false;

        db->segment_bytes = want_segment_bytes;
        db->base_generation = 1;
        db->leading_wal_id = 1;
        db->next_seq = 1;
        db->sb_generation = 1;
    } else {
        close(sbfd);
        db->segment_bytes = want_segment_bytes;
        db->base_generation = winner->base_generation;
        db->leading_wal_id = winner->leading_wal_id;
        db->next_seq = winner->next_seq;
        db->sb_generation = winner->generation;
    }

    /* Discover on-disk WAL ids; trust the highest one found as leading
     * (more robust than the superblock's cached copy if we crashed right
     * after creating a new leading file but before the checkpoint that
     * would have recorded it). */
    uint32_t ids[8192];
    uint32_t n = discover_wal_ids(db->dir_path, ids, 8192);
    if (n == 0) { errno = EINVAL; return false; }
    uint32_t leading_id = ids[n - 1];
    if (leading_id > db->leading_wal_id) db->leading_wal_id = leading_id;

    free_sealed_list(db);
    for (uint32_t i = 0; i + 1 < n; i++) {
        if (ids[i] == db->leading_wal_id) continue;
        picowal_wal_seg_t* s = (picowal_wal_seg_t*)calloc(1, sizeof(*s));
        if (!s) return false;
        s->id = ids[i];
        s->next = db->sealed_wals;
        db->sealed_wals = s;
    }

    int bfd = open(bp, O_RDWR | O_CLOEXEC, 0600);
    if (bfd < 0) return false;
    picowal_file_hdr_t bh;
    if (pread_full(bfd, &bh, sizeof(bh), 0) != 0 || !file_hdr_valid(&bh, PICOWAL_BASE_SEG_ID)) {
        close(bfd); errno = EIO; return false;
    }
    db->base_generation = bh.generation;
    struct stat bst;
    db->base_bytes = (fstat(bfd, &bst) == 0 && (uint64_t)bst.st_size > PICOWAL_SEG_DATA_START) ?
                     (uint64_t)bst.st_size - PICOWAL_SEG_DATA_START : 0;
    db->base_fd = bfd;

    char lwp[800];
    wal_path(db, db->leading_wal_id, lwp, sizeof(lwp));
    int lfd = open(lwp, O_RDWR | O_CLOEXEC, 0600);
    if (lfd < 0) { close(db->base_fd); db->base_fd = -1; return false; }
    picowal_file_hdr_t lh;
    if (pread_full(lfd, &lh, sizeof(lh), 0) != 0 || !file_hdr_valid(&lh, db->leading_wal_id)) {
        close(lfd); close(db->base_fd); db->base_fd = -1; errno = EIO; return false;
    }
    db->leading_fd = lfd;
    db->leading_write_off = PICOWAL_SEG_DATA_START;
    db->appends_since_checkpoint = 0;
    return true;
}

/* ============================================================ append */

/* Appends one record to the leading WAL segment. txn_id_in == 0 means
 * "this record starts a new transaction" (its own seq becomes the
 * txn_id, returned via *out_seq which the caller reuses for subsequent
 * ops in the same explicit transaction). allow_rotate controls whether
 * hitting the segment cap seals the current leading segment and starts a
 * new one (implicit ops: true; continuation writes inside an explicit
 * transaction: false, so a transaction never spans two files -- it just
 * fails with ENOSPC instead, matching the "keep transactions short-lived"
 * contract). do_fsync controls whether this call blocks on fdatasync (the
 * FIRE_AND_FORGET durability level defers that to the background
 * flusher). Caller must hold db->mu. */
static int append_record_locked(picowal_db_t* db, uint32_t key, const uint8_t* data,
                                uint32_t len, bool tombstone, uint64_t txn_id_in,
                                bool is_final, bool allow_rotate, bool do_fsync,
                                uint32_t* out_seg_id, uint64_t* out_offset, uint64_t* out_seq) {
    if (db->leading_fd < 0) { errno = EBADF; return -1; }

    uint64_t span = align_up_512(sizeof(picowal_record_hdr_t) + len);
    if (db->leading_write_off + span > db->segment_bytes) {
        if (!allow_rotate) { errno = ENOSPC; return -1; }

        uint32_t new_id = db->leading_wal_id + 1;
        char wp[800];
        wal_path(db, new_id, wp, sizeof(wp));
        int wfd = open(wp, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (wfd < 0) return -1;
        if (!write_file_header(wfd, new_id, 1) || fdatasync(wfd) != 0) {
            int e = errno; close(wfd); errno = e; return -1;
        }
        fdatasync(db->leading_fd); /* seal the old leading segment durably */

        picowal_wal_seg_t* sealed = (picowal_wal_seg_t*)calloc(1, sizeof(*sealed));
        if (!sealed) { close(wfd); errno = ENOMEM; return -1; }
        sealed->id = db->leading_wal_id;
        sealed->next = db->sealed_wals;
        db->sealed_wals = sealed;

        close(db->leading_fd);
        db->leading_fd = wfd;
        db->leading_wal_id = new_id;
        db->leading_write_off = PICOWAL_SEG_DATA_START;
        write_superblock_locked(db); /* durably record the rotation */

        if (db->leading_write_off + span > db->segment_bytes) { errno = E2BIG; return -1; }
    }

    picowal_record_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.magic = PICOWAL_REC_MAGIC;
    h.key = key;
    h.len = len;
    h.seq = db->next_seq++;
    h.txn_id = (txn_id_in == 0) ? h.seq : txn_id_in;
    h.flags = (tombstone ? PICOWAL_REC_TOMBSTONE : 0u) | (is_final ? PICOWAL_REC_TXN_COMMIT : 0u);
    h.checksum = rec_checksum(h.key, h.len, h.flags, h.seq, h.txn_id, data);

    uint64_t rec_off = db->leading_write_off;
    if (pwrite_full(db->leading_fd, &h, sizeof(h), rec_off) != 0) return -1;
    if (len > 0 && pwrite_full(db->leading_fd, data, len, rec_off + sizeof(h)) != 0) return -1;

    uint64_t pad = span - (sizeof(h) + len);
    if (pad > 0) {
        static const uint8_t zeros[PICOWAL_SECTOR_BYTES] = {0};
        uint64_t woff = rec_off + sizeof(h) + len;
        while (pad > 0) {
            size_t chunk = (pad > sizeof(zeros)) ? sizeof(zeros) : (size_t)pad;
            if (pwrite_full(db->leading_fd, zeros, chunk, woff) != 0) return -1;
            woff += chunk;
            pad -= chunk;
        }
    }
    if (do_fsync && fdatasync(db->leading_fd) != 0) return -1;

    db->leading_write_off += span;
    *out_seg_id = db->leading_wal_id;
    *out_offset = rec_off;
    *out_seq = h.seq;
    return 0;
}

/* Rewrites just the header of an already-written record to add the
 * TXN_COMMIT flag (used at explicit-transaction commit time), recomputing
 * its checksum. Caller must hold db->mu; the record must be in the
 * current leading segment. */
static int mark_committed_locked(picowal_db_t* db, uint64_t offset, uint32_t key,
                                 uint32_t len, uint64_t seq, uint64_t txn_id, bool tombstone) {
    uint8_t payload[PICOWAL_DATA_MAX];
    if (len > 0 && pread_full(db->leading_fd, payload, len, offset + sizeof(picowal_record_hdr_t)) != 0)
        return -1;

    picowal_record_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.magic = PICOWAL_REC_MAGIC;
    h.key = key;
    h.len = len;
    h.seq = seq;
    h.txn_id = txn_id;
    h.flags = (tombstone ? PICOWAL_REC_TOMBSTONE : 0u) | PICOWAL_REC_TXN_COMMIT;
    h.checksum = rec_checksum(h.key, h.len, h.flags, h.seq, h.txn_id, len ? payload : NULL);
    return pwrite_full(db->leading_fd, &h, sizeof(h), offset);
}

/* ============================================================ ack registry */

static void ack_registry_init(picowal_db_t* db) {
    pthread_mutex_init(&db->ack_mu, NULL);
    pthread_cond_init(&db->ack_cv, NULL);
    db->ack_quorum = 1;
}

void picowal_db_repl_ack_register(picowal_db_t* db, const char* replica_id) {
    if (!db || !replica_id) return;
    pthread_mutex_lock(&db->ack_mu);
    bool found = false;
    for (uint32_t i = 0; i < PICOWAL_MAX_REPLICA_ACKS; i++) {
        if (db->acks[i].used && strncmp(db->acks[i].id, replica_id, sizeof(db->acks[i].id)) == 0) {
            found = true; break;
        }
    }
    if (!found) {
        for (uint32_t i = 0; i < PICOWAL_MAX_REPLICA_ACKS; i++) {
            if (!db->acks[i].used) {
                db->acks[i].used = true;
                snprintf(db->acks[i].id, sizeof(db->acks[i].id), "%s", replica_id);
                db->acks[i].seg_id = 0;
                db->acks[i].offset = 0;
                break;
            }
        }
    }
    pthread_mutex_unlock(&db->ack_mu);
}

void picowal_db_repl_ack(picowal_db_t* db, const char* replica_id, uint32_t seg_id, uint64_t offset) {
    if (!db || !replica_id) return;
    pthread_mutex_lock(&db->ack_mu);
    int slot = -1;
    for (uint32_t i = 0; i < PICOWAL_MAX_REPLICA_ACKS; i++) {
        if (db->acks[i].used && strncmp(db->acks[i].id, replica_id, sizeof(db->acks[i].id)) == 0) {
            slot = (int)i; break;
        }
    }
    if (slot < 0) {
        for (uint32_t i = 0; i < PICOWAL_MAX_REPLICA_ACKS; i++) {
            if (!db->acks[i].used) { slot = (int)i; break; }
        }
    }
    if (slot >= 0) {
        db->acks[slot].used = true;
        snprintf(db->acks[slot].id, sizeof(db->acks[slot].id), "%s", replica_id);
        db->acks[slot].seg_id = seg_id;
        db->acks[slot].offset = offset;
    }
    pthread_cond_broadcast(&db->ack_cv);
    pthread_mutex_unlock(&db->ack_mu);
}

void picowal_db_repl_ack_set_quorum(picowal_db_t* db, uint32_t min_replica_acks) {
    if (!db) return;
    pthread_mutex_lock(&db->ack_mu);
    db->ack_quorum = (min_replica_acks == 0) ? 1 : min_replica_acks;
    pthread_mutex_unlock(&db->ack_mu);
}

static void wait_for_ack_quorum(picowal_db_t* db, uint32_t seg_id, uint64_t offset, bool* out_replicated) {
    pthread_mutex_lock(&db->ack_mu);
    uint32_t registered = 0;
    for (uint32_t i = 0; i < PICOWAL_MAX_REPLICA_ACKS; i++) if (db->acks[i].used) registered++;
    if (registered == 0) {
        pthread_mutex_unlock(&db->ack_mu);
        if (out_replicated) *out_replicated = false;
        return;
    }

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += PICOWAL_REPL_ACK_TIMEOUT_MS / 1000;
    deadline.tv_nsec += (long)(PICOWAL_REPL_ACK_TIMEOUT_MS % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec += 1; deadline.tv_nsec -= 1000000000L; }

    bool ok = false;
    for (;;) {
        uint32_t acked = 0;
        for (uint32_t i = 0; i < PICOWAL_MAX_REPLICA_ACKS; i++) {
            if (db->acks[i].used && db->acks[i].seg_id == seg_id && db->acks[i].offset >= offset) acked++;
        }
        if (acked >= db->ack_quorum) { ok = true; break; }
        int wr = pthread_cond_timedwait(&db->ack_cv, &db->ack_mu, &deadline);
        if (wr == ETIMEDOUT) break;
    }
    pthread_mutex_unlock(&db->ack_mu);
    if (out_replicated) *out_replicated = ok;
}

/* ============================================================ lifecycle */

picowal_db_t* picowal_db_create(void) {
    picowal_db_t* db = (picowal_db_t*)calloc(1, sizeof(*db));
    if (!db) return NULL;
    db->base_fd = -1;
    db->leading_fd = -1;
    pthread_mutex_init(&db->mu, NULL);
    ack_registry_init(db);
    return db;
}

void picowal_db_close(picowal_db_t* db) {
    if (!db) return;
    pthread_mutex_lock(&db->mu);
    if (db->leading_fd >= 0) {
        write_superblock_locked(db);
        close(db->leading_fd);
        db->leading_fd = -1;
    }
    if (db->base_fd >= 0) { close(db->base_fd); db->base_fd = -1; }
    free_sealed_list(db);
    clear_index(db);
    db->leading_write_off = 0;
    db->next_seq = 1;
    db->sb_generation = 0;
    db->appends_since_checkpoint = 0;
    pthread_mutex_unlock(&db->mu);
}

void picowal_db_destroy(picowal_db_t* db) {
    if (!db) return;
    picowal_db_close(db);
    pthread_mutex_destroy(&db->mu);
    pthread_mutex_destroy(&db->ack_mu);
    pthread_cond_destroy(&db->ack_cv);
    free(db);
}

bool picowal_db_pack_key(uint16_t card, uint32_t record, uint32_t* out_key) {
    if (!out_key || card > PICOWAL_CARD_MAX || record > PICOWAL_RECORD_MAX) return false;
    *out_key = ((uint32_t)card << 22) | (record & 0x003fffffu);
    return true;
}

void picowal_db_unpack_key(uint32_t key, uint16_t* card_out, uint32_t* record_out) {
    if (card_out) *card_out = (uint16_t)((key >> 22) & 0x3ffu);
    if (record_out) *record_out = key & 0x003fffffu;
}

bool picowal_db_open(picowal_db_t* db, const char* device_path,
                    uint64_t segment_bytes, bool format) {
    if (!db || !device_path || !device_path[0]) { errno = EINVAL; return false; }
    pthread_mutex_lock(&db->mu);
    if (db->leading_fd >= 0) { close(db->leading_fd); db->leading_fd = -1; }
    if (db->base_fd >= 0) { close(db->base_fd); db->base_fd = -1; }
    free_sealed_list(db);
    clear_index(db);

    bool ok = load_or_format(db, device_path, segment_bytes, format);
    if (ok) ok = scan_volume(db);
    if (!ok) {
        if (db->leading_fd >= 0) { close(db->leading_fd); db->leading_fd = -1; }
        if (db->base_fd >= 0) { close(db->base_fd); db->base_fd = -1; }
    }
    pthread_mutex_unlock(&db->mu);
    return ok;
}

void picowal_db_set_read_only(picowal_db_t* db, bool read_only) {
    if (!db) return;
    pthread_mutex_lock(&db->mu);
    db->read_only = read_only;
    pthread_mutex_unlock(&db->mu);
}

const char* picowal_db_path(picowal_db_t* db) { return db ? db->dir_path : NULL; }

uint64_t picowal_db_segment_bytes(picowal_db_t* db) {
    if (!db) return 0;
    pthread_mutex_lock(&db->mu);
    uint64_t v = db->segment_bytes;
    pthread_mutex_unlock(&db->mu);
    return v;
}

/* ============================================================ explicit transactions */

picowal_txn_t* picowal_db_txn_begin(picowal_db_t* db) {
    if (!db) { errno = EINVAL; return NULL; }
    pthread_mutex_lock(&db->mu);
    if (db->read_only) { pthread_mutex_unlock(&db->mu); errno = EROFS; return NULL; }
    picowal_txn_t* txn = (picowal_txn_t*)calloc(1, sizeof(*txn));
    if (!txn) { pthread_mutex_unlock(&db->mu); errno = ENOMEM; return NULL; }
    txn->db = db;
    txn->seg_id = db->leading_wal_id;
    return txn; /* db->mu stays held until commit/rollback */
}

static int txn_append(picowal_txn_t* txn, uint32_t key, const uint8_t* data,
                      uint32_t len, bool tombstone) {
    if (txn->op_count >= PICOWAL_TXN_MAX_OPS) { errno = E2BIG; return -1; }
    uint32_t seg_id = 0; uint64_t offset = 0, seq = 0;
    if (append_record_locked(txn->db, key, data, len, tombstone, txn->txn_id,
                             false /* is_final */, false /* allow_rotate */,
                             false /* do_fsync: deferred to commit */,
                             &seg_id, &offset, &seq) != 0) {
        return -1;
    }
    if (txn->txn_id == 0) txn->txn_id = seq;
    txn->ops[txn->op_count].key = key;
    txn->ops[txn->op_count].seg_id = seg_id;
    txn->ops[txn->op_count].offset = offset;
    txn->ops[txn->op_count].len = len;
    txn->ops[txn->op_count].seq = seq;
    txn->ops[txn->op_count].tombstone = tombstone;
    txn->op_count++;
    txn->last_hdr_offset = offset;
    return 0;
}

int picowal_db_txn_put(picowal_txn_t* txn, uint32_t key, const void* data,
                      uint32_t len, bool create_only) {
    if (!txn || !data || len == 0 || len > PICOWAL_DATA_MAX) { errno = EINVAL; return -1; }
    if (create_only) {
        picowal_index_entry_t* e = index_find(txn->db, key);
        if (e && !e->tombstone) { errno = EEXIST; return -1; }
    }
    return txn_append(txn, key, (const uint8_t*)data, len, false);
}

int picowal_db_txn_delete(picowal_txn_t* txn, uint32_t key) {
    if (!txn) { errno = EINVAL; return -1; }
    picowal_index_entry_t* e = index_find(txn->db, key);
    if (!e || e->tombstone) { errno = ENOENT; return -1; }
    return txn_append(txn, key, NULL, 0, true);
}

int picowal_db_txn_commit(picowal_txn_t* txn, picowal_durability_t durability, bool* out_replicated) {
    if (!txn) { errno = EINVAL; return -1; }
    picowal_db_t* db = txn->db;
    if (out_replicated) *out_replicated = false;

    if (txn->op_count == 0) {
        pthread_mutex_unlock(&db->mu);
        free(txn);
        return 0;
    }

    uint32_t last = txn->op_count - 1;
    if (mark_committed_locked(db, txn->ops[last].offset, txn->ops[last].key,
                              txn->ops[last].len, txn->ops[last].seq, txn->txn_id,
                              txn->ops[last].tombstone) != 0) {
        int e = errno;
        pthread_mutex_unlock(&db->mu);
        free(txn);
        errno = e;
        return -1;
    }

    if (durability != PICOWAL_DURABILITY_FIRE_AND_FORGET) {
        if (fdatasync(db->leading_fd) != 0) {
            int e = errno;
            pthread_mutex_unlock(&db->mu);
            free(txn);
            errno = e;
            return -1;
        }
    } else {
        db->dirty_unsynced = true;
    }

    for (uint32_t i = 0; i < txn->op_count; i++) {
        index_upsert(db, txn->ops[i].key, txn->ops[i].seg_id, txn->ops[i].offset,
                    txn->ops[i].len, txn->ops[i].seq, txn->ops[i].tombstone);
        uint16_t card = 0; uint32_t recid = 0;
        picowal_db_unpack_key(txn->ops[i].key, &card, &recid);
        if (card == 1 || card == 2) db->schema_gen++;
    }
    db->appends_since_checkpoint += txn->op_count;
    if (db->appends_since_checkpoint >= PICOWAL_SB_CHECKPOINT_INTERVAL) write_superblock_locked(db);

    uint32_t final_seg = txn->ops[last].seg_id;
    uint64_t final_off = db->leading_write_off; /* current leading tail after this txn */
    pthread_mutex_unlock(&db->mu);
    free(txn);

    if (durability == PICOWAL_DURABILITY_REPLICATED) {
        wait_for_ack_quorum(db, final_seg, final_off, out_replicated);
    }
    return 0;
}

void picowal_db_txn_rollback(picowal_txn_t* txn) {
    if (!txn) return;
    /* Already-written bytes for this txn are simply abandoned in place --
     * never indexed, so they're invisible to every reader, and get
     * reclaimed either by the next open's scan (rolls write_off back) or
     * by a future checkpoint once this segment seals. No on-disk
     * bookkeeping needed. */
    pthread_mutex_unlock(&txn->db->mu);
    free(txn);
}

/* ============================================================ implicit (auto-commit) ops */

int picowal_db_put_key_dur(picowal_db_t* db, uint32_t key, const void* data, uint32_t len,
                          bool create_only, picowal_durability_t durability, bool* out_replicated) {
    if (out_replicated) *out_replicated = false;
    if (!db || !data || len == 0 || len > PICOWAL_DATA_MAX) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&db->mu);
    if (db->read_only) { pthread_mutex_unlock(&db->mu); errno = EROFS; return -1; }
    if (create_only) {
        picowal_index_entry_t* e = index_find(db, key);
        if (e && !e->tombstone) { pthread_mutex_unlock(&db->mu); errno = EEXIST; return -1; }
    }
    uint32_t seg_id = 0; uint64_t offset = 0, seq = 0;
    bool do_fsync = durability != PICOWAL_DURABILITY_FIRE_AND_FORGET;
    if (append_record_locked(db, key, (const uint8_t*)data, len, false, 0, true, true,
                             do_fsync, &seg_id, &offset, &seq) != 0) {
        int e = errno;
        pthread_mutex_unlock(&db->mu);
        errno = e;
        return -1;
    }
    if (!do_fsync) db->dirty_unsynced = true;
    index_upsert(db, key, seg_id, offset, len, seq, false);
    if (++db->appends_since_checkpoint >= PICOWAL_SB_CHECKPOINT_INTERVAL) write_superblock_locked(db);
    uint64_t tail = db->leading_write_off;
    {
        uint16_t card = 0; uint32_t rec = 0;
        picowal_db_unpack_key(key, &card, &rec);
        if (card == 1 || card == 2) db->schema_gen++;
    }
    pthread_mutex_unlock(&db->mu);

    if (durability == PICOWAL_DURABILITY_REPLICATED) wait_for_ack_quorum(db, seg_id, tail, out_replicated);
    return 0;
}

int picowal_db_delete_key_dur(picowal_db_t* db, uint32_t key,
                             picowal_durability_t durability, bool* out_replicated) {
    if (out_replicated) *out_replicated = false;
    if (!db) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&db->mu);
    if (db->read_only) { pthread_mutex_unlock(&db->mu); errno = EROFS; return -1; }
    picowal_index_entry_t* e = index_find(db, key);
    if (!e || e->tombstone) { pthread_mutex_unlock(&db->mu); errno = ENOENT; return -1; }
    uint32_t seg_id = 0; uint64_t offset = 0, seq = 0;
    bool do_fsync = durability != PICOWAL_DURABILITY_FIRE_AND_FORGET;
    if (append_record_locked(db, key, NULL, 0, true, 0, true, true, do_fsync,
                             &seg_id, &offset, &seq) != 0) {
        int err = errno;
        pthread_mutex_unlock(&db->mu);
        errno = err;
        return -1;
    }
    if (!do_fsync) db->dirty_unsynced = true;
    index_upsert(db, key, seg_id, offset, 0, seq, true);
    if (++db->appends_since_checkpoint >= PICOWAL_SB_CHECKPOINT_INTERVAL) write_superblock_locked(db);
    uint64_t tail = db->leading_write_off;
    {
        uint16_t card = 0; uint32_t rec = 0;
        picowal_db_unpack_key(key, &card, &rec);
        if (card == 1 || card == 2) db->schema_gen++;
    }
    pthread_mutex_unlock(&db->mu);

    if (durability == PICOWAL_DURABILITY_REPLICATED) wait_for_ack_quorum(db, seg_id, tail, out_replicated);
    return 0;
}

int picowal_db_put_key(picowal_db_t* db, uint32_t key, const void* data, uint32_t len, bool create_only) {
    return picowal_db_put_key_dur(db, key, data, len, create_only, PICOWAL_DURABILITY_LOCAL, NULL);
}

int picowal_db_delete_key(picowal_db_t* db, uint32_t key) {
    return picowal_db_delete_key_dur(db, key, PICOWAL_DURABILITY_LOCAL, NULL);
}

uint64_t picowal_db_schema_generation(picowal_db_t* db) {
    if (!db) return 0;
    return db->schema_gen;
}

/* ============================================================ reads */

int picowal_db_get_key(picowal_db_t* db, uint32_t key, void* out, uint32_t out_len) {
    if (!db || !out || out_len == 0) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&db->mu);
    picowal_index_entry_t* e = index_find(db, key);
    if (!e || e->tombstone) { pthread_mutex_unlock(&db->mu); errno = ENOENT; return -1; }
    if (e->len > out_len) { pthread_mutex_unlock(&db->mu); errno = EMSGSIZE; return -1; }

    uint32_t seg_id = e->seg_id; uint64_t offset = e->offset; uint32_t len = e->len;
    bool should_close = false;
    int fd = resolve_read_fd(db, seg_id, &should_close);
    if (fd < 0) { pthread_mutex_unlock(&db->mu); errno = EIO; return -1; }

    picowal_record_hdr_t h;
    int rc = pread_full(fd, &h, sizeof(h), offset);
    if (rc == 0 && (h.magic != PICOWAL_REC_MAGIC || h.key != key || h.len != len ||
                   (h.flags & PICOWAL_REC_TOMBSTONE) != 0)) {
        rc = -1; errno = EIO;
    }
    if (rc == 0 && len > 0) rc = pread_full(fd, out, len, offset + sizeof(h));
    if (rc == 0) {
        uint64_t chk = rec_checksum(h.key, h.len, h.flags, h.seq, h.txn_id, len ? (const uint8_t*)out : NULL);
        if (chk != h.checksum) { rc = -1; errno = EIO; }
    }
    if (should_close) close(fd);
    pthread_mutex_unlock(&db->mu);
    return rc == 0 ? (int)len : -1;
}

bool picowal_db_exists_key(picowal_db_t* db, uint32_t key) {
    if (!db) return false;
    pthread_mutex_lock(&db->mu);
    picowal_index_entry_t* e = index_find(db, key);
    bool ok = (e && !e->tombstone);
    pthread_mutex_unlock(&db->mu);
    return ok;
}

uint32_t picowal_db_list_records(picowal_db_t* db, uint16_t card, uint32_t* out_records, uint32_t max_records) {
    if (!db || !out_records || max_records == 0 || card > PICOWAL_CARD_MAX) return 0;
    uint32_t n = 0;
    pthread_mutex_lock(&db->mu);
    for (size_t bi = 0; bi < PICOWAL_INDEX_BUCKETS && n < max_records; bi++) {
        for (picowal_index_entry_t* e = db->buckets[bi]; e && n < max_records; e = e->next) {
            if (!e->tombstone && (((e->key >> 22) & 0x3ffu) == card)) {
                out_records[n++] = e->key & 0x003fffffu;
            }
        }
    }
    pthread_mutex_unlock(&db->mu);
    return n;
}

/* ============================================================ checkpoint */

void picowal_db_usage_stats(picowal_db_t* db, uint64_t* out_wal_bytes,
                           uint64_t* out_live_bytes, uint32_t* out_live_records) {
    if (!db) return;
    pthread_mutex_lock(&db->mu);
    uint64_t wal_bytes = 0;
    for (picowal_wal_seg_t* s = db->sealed_wals; s; s = s->next) {
        char path[800];
        wal_path(db, s->id, path, sizeof(path));
        struct stat st;
        if (stat(path, &st) == 0 && (uint64_t)st.st_size > PICOWAL_SEG_DATA_START)
            wal_bytes += (uint64_t)st.st_size - PICOWAL_SEG_DATA_START;
    }
    uint64_t live_bytes = 0;
    uint32_t live_records = 0;
    for (size_t bi = 0; bi < PICOWAL_INDEX_BUCKETS; bi++) {
        for (picowal_index_entry_t* e = db->buckets[bi]; e; e = e->next) {
            if (e->tombstone || e->seg_id == db->leading_wal_id) continue;
            live_bytes += align_up_512(sizeof(picowal_record_hdr_t) + e->len);
            live_records++;
        }
    }
    pthread_mutex_unlock(&db->mu);
    if (out_wal_bytes) *out_wal_bytes = wal_bytes;
    if (out_live_bytes) *out_live_bytes = live_bytes;
    if (out_live_records) *out_live_records = live_records;
}

int picowal_db_checkpoint(picowal_db_t* db, uint64_t* out_bytes_reclaimed, uint32_t* out_segments_removed) {
    if (!db) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&db->mu);
    if (db->read_only) { pthread_mutex_unlock(&db->mu); errno = EROFS; return -1; }
    if (!db->sealed_wals) {
        pthread_mutex_unlock(&db->mu);
        if (out_bytes_reclaimed) *out_bytes_reclaimed = 0;
        if (out_segments_removed) *out_segments_removed = 0;
        return 0;
    }

    typedef struct { uint32_t key; uint32_t seg_id; uint64_t offset; uint32_t len; uint64_t seq; } fold_t;
    uint32_t cap = 0;
    for (size_t bi = 0; bi < PICOWAL_INDEX_BUCKETS; bi++)
        for (picowal_index_entry_t* e = db->buckets[bi]; e; e = e->next) cap++;
    fold_t* fold = cap ? (fold_t*)calloc(cap, sizeof(fold_t)) : NULL;
    uint32_t fold_n = 0;
    if (cap && !fold) { pthread_mutex_unlock(&db->mu); errno = ENOMEM; return -1; }

    for (size_t bi = 0; bi < PICOWAL_INDEX_BUCKETS; bi++) {
        for (picowal_index_entry_t* e = db->buckets[bi]; e; e = e->next) {
            if (e->tombstone || e->seg_id == db->leading_wal_id) continue;
            fold[fold_n].key = e->key; fold[fold_n].seg_id = e->seg_id;
            fold[fold_n].offset = e->offset; fold[fold_n].len = e->len; fold[fold_n].seq = e->seq;
            fold_n++;
        }
    }
    /* stable-ish chronological order */
    for (uint32_t i = 1; i < fold_n; i++) {
        fold_t v = fold[i]; uint32_t j = i;
        while (j > 0 && fold[j - 1].seq > v.seq) { fold[j] = fold[j - 1]; j--; }
        fold[j] = v;
    }

    char bp[800];
    base_path(db, bp, sizeof(bp));
    char tmp_bp[820];
    snprintf(tmp_bp, sizeof(tmp_bp), "%s.ckpt_tmp", bp);
    int tfd = open(tmp_bp, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (tfd < 0) { free(fold); pthread_mutex_unlock(&db->mu); return -1; }

    uint32_t new_generation = db->base_generation + 1;
    if (!write_file_header(tfd, PICOWAL_BASE_SEG_ID, new_generation)) {
        int e = errno; close(tfd); unlink(tmp_bp); free(fold); pthread_mutex_unlock(&db->mu); errno = e; return -1;
    }

    uint64_t w = PICOWAL_SEG_DATA_START;
    uint8_t payload[PICOWAL_DATA_MAX];
    bool io_ok = true;
    for (uint32_t i = 0; i < fold_n && io_ok; i++) {
        bool should_close = false;
        int rfd = resolve_read_fd(db, fold[i].seg_id, &should_close);
        if (rfd < 0) { io_ok = false; break; }
        picowal_record_hdr_t h;
        if (pread_full(rfd, &h, sizeof(h), fold[i].offset) != 0 || h.magic != PICOWAL_REC_MAGIC ||
            h.key != fold[i].key || h.len != fold[i].len) {
            if (should_close) close(rfd);
            io_ok = false; break;
        }
        if (h.len > 0 && pread_full(rfd, payload, h.len, fold[i].offset + sizeof(h)) != 0) {
            if (should_close) close(rfd);
            io_ok = false; break;
        }
        if (should_close) close(rfd);

        picowal_record_hdr_t nh;
        memset(&nh, 0, sizeof(nh));
        nh.magic = PICOWAL_REC_MAGIC;
        nh.key = h.key; nh.len = h.len; nh.seq = h.seq; nh.txn_id = h.seq;
        nh.flags = PICOWAL_REC_TXN_COMMIT; /* live records only: never a tombstone here */
        nh.checksum = rec_checksum(nh.key, nh.len, nh.flags, nh.seq, nh.txn_id, nh.len ? payload : NULL);

        uint64_t span = align_up_512(sizeof(nh) + nh.len);
        if (pwrite_full(tfd, &nh, sizeof(nh), w) != 0) { io_ok = false; break; }
        if (nh.len > 0 && pwrite_full(tfd, payload, nh.len, w + sizeof(nh)) != 0) { io_ok = false; break; }
        uint64_t pad = span - (sizeof(nh) + nh.len);
        if (pad > 0) {
            static const uint8_t zeros[PICOWAL_SECTOR_BYTES] = {0};
            uint64_t woff = w + sizeof(nh) + nh.len;
            while (pad > 0) {
                size_t chunk = (pad > sizeof(zeros)) ? sizeof(zeros) : (size_t)pad;
                if (pwrite_full(tfd, zeros, chunk, woff) != 0) { io_ok = false; break; }
                woff += chunk; pad -= chunk;
            }
            if (!io_ok) break;
        }
        fold[i].offset = w; /* new physical offset in the rewritten base.dat */
        w += span;
    }
    if (io_ok && fdatasync(tfd) != 0) io_ok = false;
    close(tfd);
    if (!io_ok) { unlink(tmp_bp); free(fold); pthread_mutex_unlock(&db->mu); return -1; }

    if (rename(tmp_bp, bp) != 0) { free(fold); pthread_mutex_unlock(&db->mu); return -1; }

    int newbfd = open(bp, O_RDWR | O_CLOEXEC, 0600);
    if (newbfd < 0) { free(fold); pthread_mutex_unlock(&db->mu); return -1; }
    if (db->base_fd >= 0) close(db->base_fd);
    db->base_fd = newbfd;
    db->base_generation = new_generation;
    db->base_bytes = w - PICOWAL_SEG_DATA_START;

    index_drop_segment(db, PICOWAL_BASE_SEG_ID);
    for (picowal_wal_seg_t* s = db->sealed_wals; s; s = s->next) index_drop_segment(db, s->id);
    for (uint32_t i = 0; i < fold_n; i++)
        index_upsert(db, fold[i].key, PICOWAL_BASE_SEG_ID, fold[i].offset, fold[i].len, fold[i].seq, false);
    free(fold);

    uint64_t reclaimed = 0;
    uint32_t removed = 0;
    picowal_wal_seg_t* s = db->sealed_wals;
    while (s) {
        char wp[800];
        wal_path(db, s->id, wp, sizeof(wp));
        struct stat st;
        if (stat(wp, &st) == 0) reclaimed += (uint64_t)st.st_size;
        unlink(wp);
        removed++;
        picowal_wal_seg_t* n = s->next;
        free(s);
        s = n;
    }
    db->sealed_wals = NULL;

    db->appends_since_checkpoint = 0;
    write_superblock_locked(db);
    pthread_mutex_unlock(&db->mu);

    if (out_bytes_reclaimed) *out_bytes_reclaimed = reclaimed;
    if (out_segments_removed) *out_segments_removed = removed;
    return 0;
}

/* ============================================================ background threads */

static void* checkpoint_thread(void* arg) {
    picowal_db_t* db = (picowal_db_t*)arg;
    for (;;) {
        sleep(PICOWAL_WAL_CHECK_INTERVAL_SEC);
        pthread_mutex_lock(&db->mu);
        bool eligible = db->leading_fd >= 0 && !db->read_only;
        pthread_mutex_unlock(&db->mu);
        if (!eligible) continue;

        uint64_t wal_bytes = 0, live_bytes = 0;
        uint32_t live_records = 0;
        picowal_db_usage_stats(db, &wal_bytes, &live_bytes, &live_records);
        if (wal_bytes < PICOWAL_WAL_MIN_RECLAIMABLE_BYTES) continue;
        uint64_t reclaimable = (wal_bytes > live_bytes) ? (wal_bytes - live_bytes) : 0;
        if ((double)reclaimable < (double)wal_bytes * PICOWAL_WAL_MIN_RECLAIMABLE_RATIO) continue;

        uint64_t bytes_reclaimed = 0; uint32_t segments_removed = 0;
        if (picowal_db_checkpoint(db, &bytes_reclaimed, &segments_removed) == 0) {
            if (segments_removed > 0) {
                fprintf(stderr, "picowal_db: checkpoint folded %u WAL segment(s), "
                        "%llu bytes reclaimed\n", segments_removed,
                        (unsigned long long)bytes_reclaimed);
            }
        } else {
            fprintf(stderr, "picowal_db: auto-checkpoint failed: %s\n", strerror(errno));
        }
    }
    return NULL;
}

static void* flusher_thread(void* arg) {
    picowal_db_t* db = (picowal_db_t*)arg;
    for (;;) {
        usleep(PICOWAL_FLUSH_INTERVAL_MS * 1000);
        if (!db->dirty_unsynced) continue;
        pthread_mutex_lock(&db->mu);
        if (db->leading_fd >= 0) fdatasync(db->leading_fd);
        db->dirty_unsynced = false;
        pthread_mutex_unlock(&db->mu);
    }
    return NULL;
}

void picowal_db_start_background_threads(picowal_db_t* db) {
    if (!db) return;
    pthread_mutex_lock(&db->mu);
    bool already = db->bg_started;
    db->bg_started = true;
    pthread_mutex_unlock(&db->mu);
    if (already) return;

    pthread_t th1, th2;
    if (pthread_create(&th1, NULL, checkpoint_thread, db) == 0) pthread_detach(th1);
    else fprintf(stderr, "picowal_db: failed to start checkpoint thread\n");
    if (pthread_create(&th2, NULL, flusher_thread, db) == 0) pthread_detach(th2);
    else fprintf(stderr, "picowal_db: failed to start flusher thread\n");
}

/* ============================================================ replication */

void picowal_db_repl_status(picowal_db_t* db, uint32_t* out_leading_wal_id,
                           uint64_t* out_leading_write_off, uint64_t* out_segment_bytes,
                           uint64_t* out_next_seq) {
    if (!db) {
        if (out_leading_wal_id) *out_leading_wal_id = 0;
        if (out_leading_write_off) *out_leading_write_off = 0;
        if (out_segment_bytes) *out_segment_bytes = 0;
        if (out_next_seq) *out_next_seq = 0;
        return;
    }
    pthread_mutex_lock(&db->mu);
    if (out_leading_wal_id) *out_leading_wal_id = db->leading_wal_id;
    if (out_leading_write_off) *out_leading_write_off = db->leading_write_off;
    if (out_segment_bytes) *out_segment_bytes = db->segment_bytes;
    if (out_next_seq) *out_next_seq = db->next_seq;
    pthread_mutex_unlock(&db->mu);
}

uint32_t picowal_db_list_segments(picowal_db_t* db, picowal_seg_info_t* out, uint32_t max_out) {
    if (!db || !out || max_out == 0) return 0;
    pthread_mutex_lock(&db->mu);
    uint32_t n = 0;
    if (n < max_out) {
        out[n].seg_id = PICOWAL_BASE_SEG_ID;
        out[n].generation = db->base_generation;
        out[n].sealed = true;
        out[n].bytes = db->base_bytes;
        n++;
    }
    /* ascending by id: collect + sort sealed wal ids first */
    uint32_t ids[8192]; uint32_t idn = 0;
    for (picowal_wal_seg_t* s = db->sealed_wals; s && idn < 8192; s = s->next) ids[idn++] = s->id;
    qsort(ids, idn, sizeof(uint32_t), seg_id_cmp);
    for (uint32_t i = 0; i < idn && n < max_out; i++) {
        char path[800];
        wal_path(db, ids[i], path, sizeof(path));
        struct stat st;
        uint64_t bytes = 0;
        if (stat(path, &st) == 0 && (uint64_t)st.st_size > PICOWAL_SEG_DATA_START)
            bytes = (uint64_t)st.st_size - PICOWAL_SEG_DATA_START;
        out[n].seg_id = ids[i];
        out[n].generation = 1;
        out[n].sealed = true;
        out[n].bytes = bytes;
        n++;
    }
    if (n < max_out && db->leading_fd >= 0) {
        out[n].seg_id = db->leading_wal_id;
        out[n].generation = 1;
        out[n].sealed = false;
        out[n].bytes = db->leading_write_off - PICOWAL_SEG_DATA_START;
        n++;
    }
    pthread_mutex_unlock(&db->mu);
    return n;
}

int picowal_db_repl_read_segment(picowal_db_t* db, uint32_t seg_id, uint32_t want_generation,
                                void* out, uint32_t* inout_len) {
    if (!db || !out || !inout_len) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&db->mu);
    if (seg_id == db->leading_wal_id) { pthread_mutex_unlock(&db->mu); errno = EROFS; return -1; }

    bool exists = (seg_id == PICOWAL_BASE_SEG_ID);
    if (!exists) for (picowal_wal_seg_t* s = db->sealed_wals; s; s = s->next) if (s->id == seg_id) { exists = true; break; }
    if (!exists) { pthread_mutex_unlock(&db->mu); errno = ENOENT; return -1; }

    uint32_t actual_gen = (seg_id == PICOWAL_BASE_SEG_ID) ? db->base_generation : 1;
    if (actual_gen != want_generation) { pthread_mutex_unlock(&db->mu); errno = ESTALE; return -1; }

    bool should_close = false;
    int fd = resolve_read_fd(db, seg_id, &should_close);
    if (fd < 0) { pthread_mutex_unlock(&db->mu); errno = ENOENT; return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        if (should_close) close(fd);
        pthread_mutex_unlock(&db->mu);
        return -1;
    }
    uint32_t want = *inout_len;
    uint64_t avail = (uint64_t)st.st_size;
    if ((uint64_t)want > avail) want = (uint32_t)avail;
    int rc = (want > 0) ? pread_full(fd, out, want, 0) : 0;
    if (should_close) close(fd);
    pthread_mutex_unlock(&db->mu);
    if (rc != 0) return -1;
    *inout_len = want;
    return 0;
}

int picowal_db_repl_read_leading(picowal_db_t* db, uint32_t seg_id, uint64_t from_off,
                                void* out, uint32_t* inout_len) {
    if (!db || !out || !inout_len || (from_off % PICOWAL_SECTOR_BYTES) != 0 ||
        from_off < PICOWAL_SEG_DATA_START) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&db->mu);
    if (seg_id != db->leading_wal_id) { pthread_mutex_unlock(&db->mu); errno = EINVAL; return -1; }
    if (from_off > db->leading_write_off) { pthread_mutex_unlock(&db->mu); errno = ERANGE; return -1; }
    uint64_t avail = db->leading_write_off - from_off;
    uint32_t want = *inout_len;
    if ((uint64_t)want > avail) want = (uint32_t)avail;
    int rc = (want > 0) ? pread_full(db->leading_fd, out, want, from_off) : 0;
    pthread_mutex_unlock(&db->mu);
    if (rc != 0) return -1;
    *inout_len = want;
    return 0;
}

int picowal_db_repl_install_segment(picowal_db_t* db, uint32_t seg_id, uint32_t generation,
                                   const void* data, uint32_t len) {
    if (!db || (!data && len > 0)) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&db->mu);
    /* seg_id colliding with our own local leading id happens in two
     * distinct cases:
     *  1) Right after a fresh format(), our local "leading" segment is
     *     just an empty placeholder (never appended to, write_off ==
     *     header-only) created before we knew the primary's real segment
     *     numbering -- safe to demote wholesale (rewrite from scratch).
     *  2) This IS the segment we've been incrementally following as our
     *     real leading via picowal_db_repl_ingest_segment(), and the
     *     primary has just sealed it by rotating -- our on-disk bytes are
     *     already byte-identical to what's being offered (rotation never
     *     appends further to the old leading segment), so this is purely
     *     an administrative transition: move it from "leading" to
     *     "sealed" bookkeeping without re-fetching/rewriting any bytes.
     * Any other mismatch (remote content longer than what we have) falls
     * through to a full wholesale rewrite, matching the pre-existing
     * behavior. */
    bool skip_rewrite = false;
    if (seg_id == db->leading_wal_id) {
        if (db->leading_write_off <= PICOWAL_SEG_DATA_START) {
            if (db->leading_fd >= 0) { close(db->leading_fd); db->leading_fd = -1; }
            db->leading_wal_id = UINT32_MAX;
            db->leading_write_off = 0;
        } else if ((uint64_t)len == db->leading_write_off) {
            /* Already have every byte the primary sealed it with. */
            if (db->leading_fd >= 0) { close(db->leading_fd); db->leading_fd = -1; }
            db->leading_wal_id = UINT32_MAX;
            db->leading_write_off = 0;
            skip_rewrite = true;
        } else {
            pthread_mutex_unlock(&db->mu); errno = EROFS; return -1;
        }
    }
    if (len < sizeof(picowal_file_hdr_t)) { pthread_mutex_unlock(&db->mu); errno = EINVAL; return -1; }
    picowal_file_hdr_t h;
    memcpy(&h, data, sizeof(h));
    if (!file_hdr_valid(&h, seg_id) || h.generation != generation) {
        pthread_mutex_unlock(&db->mu); errno = EIO; return -1;
    }

    char final_path[800], tmp_path[820];
    if (seg_id == PICOWAL_BASE_SEG_ID) base_path(db, final_path, sizeof(final_path));
    else wal_path(db, seg_id, final_path, sizeof(final_path));

    if (skip_rewrite) {
        /* Bytes on disk already match what the primary sealed it with --
         * just fold the bookkeeping (leading -> sealed) without touching
         * the file or re-scanning/re-indexing (already indexed during the
         * incremental ingest that got us here). */
        bool known = false;
        for (picowal_wal_seg_t* s = db->sealed_wals; s; s = s->next) if (s->id == seg_id) { known = true; break; }
        if (!known) {
            picowal_wal_seg_t* s = (picowal_wal_seg_t*)calloc(1, sizeof(*s));
            if (s) { s->id = seg_id; s->next = db->sealed_wals; db->sealed_wals = s; }
        }
        pthread_mutex_unlock(&db->mu);
        return 0;
    }

    snprintf(tmp_path, sizeof(tmp_path), "%s.repl_tmp", final_path);

    int fd = open(tmp_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) { pthread_mutex_unlock(&db->mu); return -1; }
    bool ok = pwrite_full(fd, data, len, 0) == 0 && fdatasync(fd) == 0;
    close(fd);
    if (!ok) { unlink(tmp_path); pthread_mutex_unlock(&db->mu); return -1; }
    if (rename(tmp_path, final_path) != 0) { unlink(tmp_path); pthread_mutex_unlock(&db->mu); return -1; }

    index_drop_segment(db, seg_id);
    if (seg_id == PICOWAL_BASE_SEG_ID) {
        if (db->base_fd >= 0) close(db->base_fd);
        db->base_fd = open(final_path, O_RDWR | O_CLOEXEC, 0600);
        db->base_generation = generation;
        db->base_bytes = (len > PICOWAL_SEG_DATA_START) ? len - PICOWAL_SEG_DATA_START : 0;
    } else {
        bool known = false;
        for (picowal_wal_seg_t* s = db->sealed_wals; s; s = s->next) if (s->id == seg_id) { known = true; break; }
        if (!known) {
            picowal_wal_seg_t* s = (picowal_wal_seg_t*)calloc(1, sizeof(*s));
            if (s) { s->id = seg_id; s->next = db->sealed_wals; db->sealed_wals = s; }
        }
    }

    uint64_t end = 0, max_seq = 0;
    bool should_close = false;
    int rfd = resolve_read_fd(db, seg_id, &should_close);
    if (rfd >= 0 && (uint64_t)len > PICOWAL_SEG_DATA_START) {
        scan_file_range(db, rfd, seg_id, PICOWAL_SEG_DATA_START, len, &end, &max_seq);
        if (max_seq + 1 > db->next_seq) db->next_seq = max_seq + 1;
    }
    if (should_close) close(rfd);
    pthread_mutex_unlock(&db->mu);
    return 0;
}

int picowal_db_repl_ingest_segment(picowal_db_t* db, uint32_t seg_id, uint64_t at_off,
                                  const void* data, uint32_t len) {
    if (!db || (!data && len > 0) || (at_off % PICOWAL_SECTOR_BYTES) != 0 ||
        (len % PICOWAL_SECTOR_BYTES) != 0) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&db->mu);

    if (seg_id != db->leading_wal_id) {
        /* Adopt as a brand new leading segment: seal the current one and
         * create this one with a header, starting at offset 0. */
        if (at_off != PICOWAL_SEG_DATA_START && at_off != 0) {
            pthread_mutex_unlock(&db->mu); errno = EINVAL; return -1;
        }
        char wp[800];
        wal_path(db, seg_id, wp, sizeof(wp));
        int wfd = open(wp, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (wfd < 0) { pthread_mutex_unlock(&db->mu); return -1; }
        if (!write_file_header(wfd, seg_id, 1) || fdatasync(wfd) != 0) {
            int e = errno; close(wfd); pthread_mutex_unlock(&db->mu); errno = e; return -1;
        }
        if (db->leading_fd >= 0) {
            picowal_wal_seg_t* sealed = (picowal_wal_seg_t*)calloc(1, sizeof(*sealed));
            if (sealed) { sealed->id = db->leading_wal_id; sealed->next = db->sealed_wals; db->sealed_wals = sealed; }
            close(db->leading_fd);
        }
        db->leading_fd = wfd;
        db->leading_wal_id = seg_id;
        db->leading_write_off = PICOWAL_SEG_DATA_START;
    }

    if (at_off != db->leading_write_off) { pthread_mutex_unlock(&db->mu); errno = EINVAL; return -1; }
    if (len > 0) {
        if (pwrite_full(db->leading_fd, data, len, at_off) != 0 || fdatasync(db->leading_fd) != 0) {
            pthread_mutex_unlock(&db->mu); return -1;
        }
    }

    uint64_t end = at_off, max_seq = 0;
    if (!scan_file_range(db, db->leading_fd, seg_id, at_off, at_off + len, &end, &max_seq)) {
        pthread_mutex_unlock(&db->mu); return -1;
    }
    db->leading_write_off = end;
    if (max_seq + 1 > db->next_seq) db->next_seq = max_seq + 1;
    if (++db->appends_since_checkpoint >= PICOWAL_SB_CHECKPOINT_INTERVAL) write_superblock_locked(db);
    pthread_mutex_unlock(&db->mu);
    return 0;
}

int picowal_db_repl_drop_segment(picowal_db_t* db, uint32_t seg_id) {
    if (!db) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&db->mu);
    index_drop_segment(db, seg_id);
    picowal_wal_seg_t** pp = &db->sealed_wals;
    while (*pp) {
        if ((*pp)->id == seg_id) {
            picowal_wal_seg_t* dead = *pp;
            *pp = dead->next;
            free(dead);
        } else {
            pp = &(*pp)->next;
        }
    }
    char wp[800];
    wal_path(db, seg_id, wp, sizeof(wp));
    unlink(wp);
    pthread_mutex_unlock(&db->mu);
    return 0;
}
