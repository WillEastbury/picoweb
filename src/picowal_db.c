#include "picowal_db.h"

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/fs.h>
#include <sys/ioctl.h>
#endif

#define PICOWAL_SECTOR_SIZE 512ULL
#define PICOWAL_SUPER_MAGIC 0x50474157u /* "PWAL" */
#define PICOWAL_REC_MAGIC   0x574c5231u /* "WLR1" */
#define PICOWAL_SB_VERSION  1u

#define PICOWAL_REC_TOMBSTONE 0x01u

#define PICOWAL_INDEX_BUCKETS 4096u

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t sector_size;
    uint64_t volume_bytes;
    uint8_t reserved[496];
} picowal_superblock_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t key;
    uint32_t len;
    uint32_t flags;
    uint64_t seq;
    uint64_t checksum;
} picowal_record_hdr_t;

typedef struct picowal_index_entry {
    uint32_t key;
    uint64_t offset;
    uint32_t len;
    uint64_t seq;
    bool tombstone;
    struct picowal_index_entry* next;
} picowal_index_entry_t;

struct picowal_db {
    int fd;
    int dir_fd;
    uint64_t volume_bytes;
    uint64_t write_off;
    uint64_t next_seq;
    bool quiesced;
    pthread_mutex_t mu;
    picowal_index_entry_t* buckets[PICOWAL_INDEX_BUCKETS];
};

_Static_assert(sizeof(picowal_superblock_t) == PICOWAL_SECTOR_SIZE,
               "picowal superblock must be exactly one sector");

static size_t bucket_idx(uint32_t key) {
    return (size_t)(metal_fnv1a(&key, sizeof(key)) & (PICOWAL_INDEX_BUCKETS - 1));
}

static bool is_zeroed(const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    for (size_t i = 0; i < n; i++) {
        if (b[i] != 0) return false;
    }
    return true;
}

static uint64_t align_up_512(uint64_t n) {
    return (n + (PICOWAL_SECTOR_SIZE - 1ULL)) & ~(PICOWAL_SECTOR_SIZE - 1ULL);
}

static int pread_full(int fd, void* out, size_t len, uint64_t off) {
    size_t got = 0;
    while (got < len) {
        ssize_t r = pread(fd, (uint8_t*)out + got, len - got, (off_t)(off + got));
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int pwrite_full(int fd, const void* in, size_t len, uint64_t off) {
    size_t wrote = 0;
    while (wrote < len) {
        ssize_t w = pwrite(fd, (const uint8_t*)in + wrote, len - wrote, (off_t)(off + wrote));
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        wrote += (size_t)w;
    }
    return 0;
}

static int open_parent_dir(const char* path) {
    const char* slash = strrchr(path, '/');
    if (!slash) return open(".", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (slash == path) return open("/", O_RDONLY | O_CLOEXEC | O_DIRECTORY);

    size_t len = (size_t)(slash - path);
    if (len == 0 || len >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    char parent[PATH_MAX];
    memcpy(parent, path, len);
    parent[len] = '\0';
    return open(parent, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
}

static uint64_t rec_checksum(uint32_t key, uint32_t len, uint32_t flags,
                             uint64_t seq, const uint8_t* payload) {
    uint64_t h = metal_fnv1a_init();
    h = metal_fnv1a_step(h, &key, sizeof(key));
    h = metal_fnv1a_step(h, &len, sizeof(len));
    h = metal_fnv1a_step(h, &flags, sizeof(flags));
    h = metal_fnv1a_step(h, &seq, sizeof(seq));
    if (payload && len) h = metal_fnv1a_step(h, payload, len);
    return h;
}

static void clear_index(picowal_db_t* db) {
    for (size_t i = 0; i < PICOWAL_INDEX_BUCKETS; i++) {
        picowal_index_entry_t* e = db->buckets[i];
        while (e) {
            picowal_index_entry_t* n = e->next;
            free(e);
            e = n;
        }
        db->buckets[i] = NULL;
    }
}

static picowal_index_entry_t* index_find(picowal_db_t* db, uint32_t key) {
    picowal_index_entry_t* e = db->buckets[bucket_idx(key)];
    while (e) {
        if (e->key == key) return e;
        e = e->next;
    }
    return NULL;
}

static int index_upsert(picowal_db_t* db, uint32_t key, uint64_t off,
                        uint32_t len, uint64_t seq, bool tombstone) {
    size_t bi = bucket_idx(key);
    picowal_index_entry_t* e = db->buckets[bi];
    while (e) {
        if (e->key == key) {
            if (seq >= e->seq) {
                e->offset = off;
                e->len = len;
                e->seq = seq;
                e->tombstone = tombstone;
            }
            return 0;
        }
        e = e->next;
    }
    e = (picowal_index_entry_t*)calloc(1, sizeof(*e));
    if (!e) return -1;
    e->key = key;
    e->offset = off;
    e->len = len;
    e->seq = seq;
    e->tombstone = tombstone;
    e->next = db->buckets[bi];
    db->buckets[bi] = e;
    return 0;
}

static bool load_or_format(picowal_db_t* db, const char* path,
                           uint64_t want_bytes, bool format) {
    int fd = open(path, O_RDWR | O_CLOEXEC | O_CREAT, 0600);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return false;
    }
    if (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode)) {
        close(fd);
        errno = EINVAL;
        return false;
    }

    if (want_bytes == 0) want_bytes = PICOWAL_DEFAULT_VOLUME_BYTES;
    if ((want_bytes % PICOWAL_SECTOR_SIZE) != 0) {
        close(fd);
        errno = EINVAL;
        return false;
    }

    if (S_ISBLK(st.st_mode)) {
#ifdef __linux__
        uint64_t dev_bytes = 0;
        if (ioctl(fd, BLKGETSIZE64, &dev_bytes) == 0 &&
            dev_bytes > 0 && want_bytes > dev_bytes) {
            close(fd);
            errno = EFBIG;
            return false;
        }
#endif
    }

    picowal_superblock_t sb;
    memset(&sb, 0, sizeof(sb));
    bool have_sb = (pread_full(fd, &sb, sizeof(sb), 0) == 0) &&
                   (sb.magic == PICOWAL_SUPER_MAGIC) &&
                   (sb.version == PICOWAL_SB_VERSION) &&
                   (sb.sector_size == PICOWAL_SECTOR_SIZE) &&
                   (sb.volume_bytes >= PICOWAL_SECTOR_SIZE);

    bool should_format = format;
    if (!have_sb) {
        if (!format) {
            if (S_ISREG(st.st_mode) && st.st_size == 0) {
                should_format = true; /* empty file bootstrap */
            } else {
                close(fd);
                errno = EINVAL;
                return false;
            }
        }
    } else {
        if (want_bytes > 0 && want_bytes != sb.volume_bytes) {
            close(fd);
            errno = EINVAL;
            return false;
        }
        want_bytes = sb.volume_bytes;
    }

    if (should_format) {
        if (S_ISREG(st.st_mode) && ftruncate(fd, (off_t)want_bytes) != 0) {
            close(fd);
            return false;
        }
        memset(&sb, 0, sizeof(sb));
        sb.magic = PICOWAL_SUPER_MAGIC;
        sb.version = PICOWAL_SB_VERSION;
        sb.sector_size = PICOWAL_SECTOR_SIZE;
        sb.volume_bytes = want_bytes;
        if (pwrite_full(fd, &sb, sizeof(sb), 0) != 0 || fdatasync(fd) != 0) {
            close(fd);
            return false;
        }
    }

    int dir_fd = open_parent_dir(path);
    if (dir_fd < 0) {
        close(fd);
        return false;
    }

    db->fd = fd;
    db->dir_fd = dir_fd;
    db->volume_bytes = want_bytes;
    db->write_off = PICOWAL_SECTOR_SIZE;
    db->next_seq = 1;
    db->quiesced = false;
    return true;
}

static bool scan_volume(picowal_db_t* db) {
    uint64_t off = PICOWAL_SECTOR_SIZE;
    uint64_t max_seq = 0;
    uint8_t payload[PICOWAL_DATA_MAX];

    while (off + sizeof(picowal_record_hdr_t) <= db->volume_bytes) {
        picowal_record_hdr_t h;
        if (pread_full(db->fd, &h, sizeof(h), off) != 0) return false;
        if (is_zeroed(&h, sizeof(h))) break;
        if (h.magic != PICOWAL_REC_MAGIC) break;
        if (h.len > PICOWAL_DATA_MAX) break;
        if ((h.flags & ~PICOWAL_REC_TOMBSTONE) != 0) break;

        uint64_t span = align_up_512(sizeof(h) + h.len);
        if (off + span > db->volume_bytes) break;

        if (h.len > 0) {
            if (pread_full(db->fd, payload, h.len, off + sizeof(h)) != 0) return false;
        }
        uint64_t chk = rec_checksum(h.key, h.len, h.flags, h.seq, h.len ? payload : NULL);
        if (chk != h.checksum) break;

        if (index_upsert(db, h.key, off, h.len, h.seq, (h.flags & PICOWAL_REC_TOMBSTONE) != 0) != 0) {
            errno = ENOMEM;
            return false;
        }
        if (h.seq > max_seq) max_seq = h.seq;
        off += span;
    }

    db->write_off = off;
    db->next_seq = max_seq + 1;
    return true;
}

static int append_record_locked(picowal_db_t* db, uint32_t key,
                                const uint8_t* data, uint32_t len, bool tombstone) {
    if (db->fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (db->quiesced) {
        errno = EBUSY;
        return -1;
    }
    picowal_record_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.magic = PICOWAL_REC_MAGIC;
    h.key = key;
    h.len = len;
    h.flags = tombstone ? PICOWAL_REC_TOMBSTONE : 0u;
    h.seq = db->next_seq++;
    h.checksum = rec_checksum(h.key, h.len, h.flags, h.seq, data);

    uint64_t span = align_up_512(sizeof(h) + len);
    if (db->write_off + span > db->volume_bytes) {
        errno = ENOSPC;
        return -1;
    }

    if (pwrite_full(db->fd, &h, sizeof(h), db->write_off) != 0) return -1;
    if (len > 0 && pwrite_full(db->fd, data, len, db->write_off + sizeof(h)) != 0) return -1;

    uint64_t pad = span - (sizeof(h) + len);
    if (pad > 0) {
        static const uint8_t zeros[PICOWAL_SECTOR_SIZE] = {0};
        uint64_t woff = db->write_off + sizeof(h) + len;
        while (pad > 0) {
            size_t chunk = (pad > sizeof(zeros)) ? sizeof(zeros) : (size_t)pad;
            if (pwrite_full(db->fd, zeros, chunk, woff) != 0) return -1;
            woff += chunk;
            pad -= chunk;
        }
    }

    if (fdatasync(db->fd) != 0) return -1;

    if (index_upsert(db, key, db->write_off, len, h.seq, tombstone) != 0) {
        errno = ENOMEM;
        return -1;
    }
    db->write_off += span;
    return 0;
}

picowal_db_t* picowal_db_create(void) {
    picowal_db_t* db = (picowal_db_t*)calloc(1, sizeof(*db));
    if (!db) return NULL;
    db->fd = -1;
    db->dir_fd = -1;
    pthread_mutex_init(&db->mu, NULL);
    return db;
}

void picowal_db_destroy(picowal_db_t* db) {
    if (!db) return;
    picowal_db_close(db);
    pthread_mutex_destroy(&db->mu);
    free(db);
}

bool picowal_db_pack_key(uint16_t card, uint32_t record, uint32_t* out_key) {
    if (!out_key) return false;
    if (card > PICOWAL_CARD_MAX || record > PICOWAL_RECORD_MAX) return false;
    *out_key = ((uint32_t)card << 22) | (record & 0x003fffffu);
    return true;
}

void picowal_db_unpack_key(uint32_t key, uint16_t* card_out, uint32_t* record_out) {
    if (card_out) *card_out = (uint16_t)((key >> 22) & 0x3ffu);
    if (record_out) *record_out = key & 0x003fffffu;
}

bool picowal_db_open(picowal_db_t* db, const char* device_path,
                     uint64_t volume_bytes, bool format) {
    if (!db || !device_path || !device_path[0]) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock(&db->mu);
    if (db->fd >= 0) {
        close(db->fd);
        db->fd = -1;
    }
    if (db->dir_fd >= 0) {
        close(db->dir_fd);
        db->dir_fd = -1;
    }
    db->quiesced = false;
    clear_index(db);

    bool ok = load_or_format(db, device_path, volume_bytes, format);
    if (ok) ok = scan_volume(db);
    if (!ok && db->fd >= 0) {
        close(db->fd);
        db->fd = -1;
    }
    if (!ok && db->dir_fd >= 0) {
        close(db->dir_fd);
        db->dir_fd = -1;
    }
    pthread_mutex_unlock(&db->mu);
    return ok;
}

void picowal_db_close(picowal_db_t* db) {
    if (!db) return;
    pthread_mutex_lock(&db->mu);
    if (db->fd >= 0) {
        close(db->fd);
        db->fd = -1;
    }
    if (db->dir_fd >= 0) {
        close(db->dir_fd);
        db->dir_fd = -1;
    }
    db->quiesced = false;
    clear_index(db);
    db->write_off = PICOWAL_SECTOR_SIZE;
    db->next_seq = 1;
    db->volume_bytes = 0;
    pthread_mutex_unlock(&db->mu);
}

bool picowal_db_healthy(picowal_db_t* db) {
    if (!db) return false;
    pthread_mutex_lock(&db->mu);
    bool ok = false;
    if (db->fd >= 0) {
        struct stat st;
        ok = (fstat(db->fd, &st) == 0) &&
             (S_ISREG(st.st_mode) || S_ISBLK(st.st_mode));
    }
    pthread_mutex_unlock(&db->mu);
    return ok;
}

bool picowal_db_quiesce(picowal_db_t* db) {
    if (!db) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock(&db->mu);
    if (db->fd < 0) {
        pthread_mutex_unlock(&db->mu);
        errno = EBADF;
        return false;
    }
    if (db->quiesced) {
        pthread_mutex_unlock(&db->mu);
        return true;
    }

    db->quiesced = true;
    if (fdatasync(db->fd) != 0 || (db->dir_fd >= 0 && fsync(db->dir_fd) != 0)) {
        int saved = errno;
        db->quiesced = false;
        pthread_mutex_unlock(&db->mu);
        errno = saved;
        return false;
    }
    pthread_mutex_unlock(&db->mu);
    return true;
}

void picowal_db_resume(picowal_db_t* db) {
    if (!db) return;
    pthread_mutex_lock(&db->mu);
    db->quiesced = false;
    pthread_mutex_unlock(&db->mu);
}

bool picowal_db_is_quiesced(picowal_db_t* db) {
    if (!db) return false;
    pthread_mutex_lock(&db->mu);
    bool quiesced = db->quiesced;
    pthread_mutex_unlock(&db->mu);
    return quiesced;
}

int picowal_db_put_key(picowal_db_t* db, uint32_t key,
                       const void* data, uint32_t len, bool create_only) {
    if (!db || !data || len == 0 || len > PICOWAL_DATA_MAX) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&db->mu);
    if (db->quiesced) {
        pthread_mutex_unlock(&db->mu);
        errno = EBUSY;
        return -1;
    }
    if (create_only) {
        picowal_index_entry_t* e = index_find(db, key);
        if (e && !e->tombstone) {
            pthread_mutex_unlock(&db->mu);
            errno = EEXIST;
            return -1;
        }
    }
    int rc = append_record_locked(db, key, (const uint8_t*)data, len, false);
    pthread_mutex_unlock(&db->mu);
    return rc;
}

int picowal_db_get_key(picowal_db_t* db, uint32_t key, void* out, uint32_t out_len) {
    if (!db || !out || out_len == 0) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&db->mu);
    picowal_index_entry_t* e = index_find(db, key);
    if (!e || e->tombstone) {
        pthread_mutex_unlock(&db->mu);
        errno = ENOENT;
        return -1;
    }
    if (e->len > out_len) {
        pthread_mutex_unlock(&db->mu);
        errno = EMSGSIZE;
        return -1;
    }

    picowal_record_hdr_t h;
    if (pread_full(db->fd, &h, sizeof(h), e->offset) != 0) {
        pthread_mutex_unlock(&db->mu);
        return -1;
    }
    if (h.magic != PICOWAL_REC_MAGIC || h.key != key || h.len != e->len ||
        (h.flags & PICOWAL_REC_TOMBSTONE) != 0) {
        pthread_mutex_unlock(&db->mu);
        errno = EIO;
        return -1;
    }
    if (pread_full(db->fd, out, e->len, e->offset + sizeof(h)) != 0) {
        pthread_mutex_unlock(&db->mu);
        return -1;
    }
    uint64_t chk = rec_checksum(h.key, h.len, h.flags, h.seq, (const uint8_t*)out);
    if (chk != h.checksum) {
        pthread_mutex_unlock(&db->mu);
        errno = EIO;
        return -1;
    }
    int ret = (int)e->len;
    pthread_mutex_unlock(&db->mu);
    return ret;
}

int picowal_db_delete_key(picowal_db_t* db, uint32_t key) {
    if (!db) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&db->mu);
    if (db->quiesced) {
        pthread_mutex_unlock(&db->mu);
        errno = EBUSY;
        return -1;
    }
    picowal_index_entry_t* e = index_find(db, key);
    if (!e || e->tombstone) {
        pthread_mutex_unlock(&db->mu);
        errno = ENOENT;
        return -1;
    }
    int rc = append_record_locked(db, key, NULL, 0, true);
    pthread_mutex_unlock(&db->mu);
    return rc;
}

bool picowal_db_exists_key(picowal_db_t* db, uint32_t key) {
    if (!db) return false;
    pthread_mutex_lock(&db->mu);
    picowal_index_entry_t* e = index_find(db, key);
    bool ok = (e && !e->tombstone);
    pthread_mutex_unlock(&db->mu);
    return ok;
}

uint32_t picowal_db_list_records(picowal_db_t* db, uint16_t card,
                                 uint32_t* out_records, uint32_t max_records) {
    if (!db || !out_records || max_records == 0 || card > PICOWAL_CARD_MAX) return 0;
    uint32_t n = 0;
    pthread_mutex_lock(&db->mu);
    for (size_t bi = 0; bi < PICOWAL_INDEX_BUCKETS && n < max_records; bi++) {
        picowal_index_entry_t* e = db->buckets[bi];
        while (e && n < max_records) {
            if (!e->tombstone && (((e->key >> 22) & 0x3ffu) == card)) {
                out_records[n++] = e->key & 0x003fffffu;
            }
            e = e->next;
        }
    }
    pthread_mutex_unlock(&db->mu);
    return n;
}
