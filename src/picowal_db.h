#ifndef PICOWAL_DB_H
#define PICOWAL_DB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PICOWAL_CARD_MAX            1023U
#define PICOWAL_RECORD_MAX          4194303U
#define PICOWAL_DATA_MAX            4096U
#define PICOWAL_DEFAULT_SEGMENT_BYTES (1ULL << 30) /* 1 GiB per WAL segment */
#define PICOWAL_REPL_CHUNK_MAX       (4U * 1024U * 1024U) /* max bytes per repl fetch */

/* ============================================================
 * On-disk layout: `device_path` is a DIRECTORY containing:
 *
 *   superblock.dat         two alternating 512-byte A/B slots (crash-safe
 *                          generation-versioned checkpoint of
 *                          base_generation/leading_wal_id/
 *                          leading_write_off/next_seq).
 *   base.dat               the MAIN FILE: one checkpointed, compacted
 *                          snapshot of every key's current live record.
 *                          Rewritten wholesale (temp+rename) by
 *                          picowal_db_checkpoint(), never appended to.
 *   wal-NNNNNNNN.wal       WAL segments, NNNNNNNN = monotonically
 *                          increasing id. Exactly one -- the highest id --
 *                          is "leading" (open, being appended to); every
 *                          other one is "sealed" and read-only.
 *
 * This is a genuine write-ahead log: every mutation is appended to the
 * leading WAL segment first (optionally fsync'd, per the durability level
 * -- see picowal_durability_t below) and applied to the in-memory index
 * immediately on commit. picowal_db_checkpoint() is what makes base.dat
 * "catch up": it folds every sealed WAL segment's committed records
 * (keeping only each key's latest live version, dropping the rest and
 * all tombstones) into base.dat, then deletes those now-fully-applied
 * WAL segments outright -- exactly the classic WAL checkpoint/truncate
 * cycle. The leading segment is never touched by a checkpoint; it keeps
 * accumulating new commits and only becomes a checkpoint candidate once
 * it's sealed by rotation (reaching its size cap).
 *
 * ---- Transactions ----
 * A single picowal_db_put_key()/picowal_db_delete_key() call is an
 * implicit transaction: one record, immediately committed. Explicit
 * transactions (picowal_db_txn_begin/put/delete/commit/rollback) group
 * several mutations so they become visible -- and crash-recoverable -- as
 * one atomic unit: every record in a transaction carries the same
 * `txn_id` (the seq of the transaction's first record), and only the
 * LAST record written in a commit has its PICOWAL_REC_TXN_COMMIT flag
 * bit set. Recovery (scan_volume, and a replica's incremental ingest)
 * buffers a txn's records in memory as they're scanned and only applies
 * them to the index once it sees that commit-marked record; if the log
 * ends (crash, or a deliberate rollback that just never writes the
 * commit-marked record) before that happens, the buffered records are
 * silently discarded -- so a rollback needs no special on-disk
 * bookkeeping at all, it degrades to exactly the same "incomplete
 * transaction" case a crash produces, and a checkpoint naturally reclaims
 * the abandoned bytes later since they were never indexed.
 *
 * IMPORTANT SIMPLIFICATION: this engine has always been single-writer
 * (one primary appends; replicas only ever replay the identical byte
 * stream in the identical order). Explicit transactions extend that by
 * holding the db-wide lock for the transaction's entire
 * begin..commit/rollback lifetime -- so there is never more than one
 * transaction "in flight" at a time, txn records are always physically
 * contiguous in the log, and no other reader/writer/replication-status
 * call can observe a partially-committed transaction (they simply block
 * on the same lock until it resolves). This trades transaction
 * concurrency for a much simpler, easier-to-get-right recovery/
 * replication story; keep explicit transactions short-lived.
 *
 * ---- Durability ----
 * Every commit (implicit or explicit) takes a picowal_durability_t that
 * trades latency for how sure the caller wants to be before the call
 * returns:
 *   PICOWAL_DURABILITY_FIRE_AND_FORGET  return as soon as the record(s)
 *                                       are written to the leading WAL's
 *                                       page cache and applied to the
 *                                       in-memory index -- no fsync wait.
 *                                       A background flusher thread syncs
 *                                       opportunistically (bounded window
 *                                       of loss on an OS crash/power cut,
 *                                       not a process crash: the index
 *                                       update already happened, and nb.
 *                                       the process itself dying doesn't
 *                                       lose anything already write()'d
 *                                       to the OS, only a raw power loss
 *                                       or `sync=no` filesystem does).
 *   PICOWAL_DURABILITY_LOCAL            return only after fdatasync() on
 *                                       the leading WAL segment confirms
 *                                       the commit is on local durable
 *                                       storage. Default; matches this
 *                                       engine's original (pre-durability-
 *                                       flag) behavior.
 *   PICOWAL_DURABILITY_REPLICATED       LOCAL, plus block (bounded by
 *                                       PICOWAL_REPL_ACK_TIMEOUT_MS) until
 *                                       a quorum of registered replicas
 *                                       have ack'd having ingested at
 *                                       least this commit's offset (see
 *                                       picowal_repl.h's ack endpoint).
 *                                       Returns 0 (committed locally
 *                                       either way) even on ack timeout --
 *                                       *out_replicated (if passed) tells
 *                                       the caller whether quorum was
 *                                       actually reached, so this never
 *                                       silently downgrades durability
 *                                       expectations without telling you.
 * ============================================================ */
#define PICOWAL_SECTOR_BYTES         512ULL
#define PICOWAL_SB_SLOT_COUNT        2ULL
#define PICOWAL_SB_FILE_BYTES        (PICOWAL_SB_SLOT_COUNT * PICOWAL_SECTOR_BYTES)
#define PICOWAL_SEG_DATA_START       PICOWAL_SECTOR_BYTES /* one header sector per file (base.dat and each wal-*.wal) */
#define PICOWAL_REPL_ACK_TIMEOUT_MS  5000U

typedef struct picowal_db picowal_db_t;
typedef struct picowal_txn picowal_txn_t;

typedef enum {
    PICOWAL_DURABILITY_FIRE_AND_FORGET = 0,
    PICOWAL_DURABILITY_LOCAL = 1,
    PICOWAL_DURABILITY_REPLICATED = 2,
} picowal_durability_t;

picowal_db_t* picowal_db_create(void);
void picowal_db_destroy(picowal_db_t* db);

bool picowal_db_pack_key(uint16_t card, uint32_t record, uint32_t* out_key);
void picowal_db_unpack_key(uint32_t key, uint16_t* card_out, uint32_t* record_out);

/* device_path is a directory (see layout above). segment_bytes is the
 * leading WAL segment's rotation cap; 0 means PICOWAL_DEFAULT_SEGMENT_BYTES.
 * format=true creates the directory (and base.dat + the first WAL
 * segment) if missing. */
bool picowal_db_open(picowal_db_t* db, const char* device_path,
                     uint64_t segment_bytes, bool format);
void picowal_db_close(picowal_db_t* db);

/* Marks the volume read-only (or read-write again): used by replica-mode
 * nodes to refuse local mutations/transactions/checkpoints (they mirror
 * the primary's base.dat + WAL segments verbatim instead of deciding
 * anything for themselves). */
void picowal_db_set_read_only(picowal_db_t* db, bool read_only);

/* Install a mandatory write-fence callback (clustered picoweb primary).
 * When set, every mutation entry point (put/delete/txn_begin) calls
 * fence_fn(ctx) BEFORE appending; a false return refuses the write
 * (errno=EROFS, mapped to HTTP 503 by the API), fail-closed, without
 * touching the log. NULL clears it.
 * Set once at startup before any writer runs (standalone/replica leave
 * it unset, preserving existing behavior). The callback is invoked
 * without the db lock held, so it may do a bounded socket round-trip. */
void picowal_db_set_fence(picowal_db_t* db, bool (*fence_fn)(void*), void* ctx);

/* --- Explicit transactions ---
 * picowal_db_txn_begin() blocks until it can acquire exclusive access
 * (see the single-writer note above) and returns a handle; every
 * picowal_db_txn_put/delete() call appends a record to the leading WAL
 * segment immediately (visible to nobody yet -- not indexed until
 * commit). picowal_db_txn_commit() marks the final record committed,
 * applies every buffered record to the in-memory index, honors
 * `durability`, and releases the lock. picowal_db_txn_rollback() just
 * releases the lock without ever writing a commit marker -- the
 * already-written bytes are abandoned in place (see the "Transactions"
 * note above for why that's safe) and reclaimed by a future checkpoint.
 * Both commit and rollback free the handle; it must not be reused after. */
picowal_txn_t* picowal_db_txn_begin(picowal_db_t* db);
/* 0 on success; -1 on failure with errno set (does NOT abort the whole
 * transaction -- caller may still commit the ops that already succeeded,
 * or explicitly roll back). */
int picowal_db_txn_put(picowal_txn_t* txn, uint32_t key, const void* data,
                      uint32_t len, bool create_only);
int picowal_db_txn_delete(picowal_txn_t* txn, uint32_t key);
/* 0 once the transaction is committed LOCALLY (this only returns -1 for a
 * genuine local write failure, e.g. I/O error or ENOSPC -- NOT for a
 * REPLICATED quorum timeout, which still returns 0 since the data is
 * safely committed locally either way; *out_replicated distinguishes
 * "quorum reached" from "timed out waiting"). Frees txn either way (never
 * call anything on it again after this returns). */
int picowal_db_txn_commit(picowal_txn_t* txn, picowal_durability_t durability,
                          bool* out_replicated);
void picowal_db_txn_rollback(picowal_txn_t* txn);

/* --- Implicit (auto-commit) single-op transactions ---
 * The *_dur variants expose the durability flag; picowal_db_put_key()/
 * picowal_db_delete_key() are thin wrappers defaulting to
 * PICOWAL_DURABILITY_LOCAL (this engine's original behavior), kept for
 * existing callers. */
int picowal_db_put_key_dur(picowal_db_t* db, uint32_t key, const void* data,
                           uint32_t len, bool create_only,
                           picowal_durability_t durability, bool* out_replicated);
int picowal_db_delete_key_dur(picowal_db_t* db, uint32_t key,
                              picowal_durability_t durability, bool* out_replicated);
/* 0 on success; -1 on failure with errno set. */
int picowal_db_put_key(picowal_db_t* db, uint32_t key,
                       const void* data, uint32_t len, bool create_only);
int picowal_db_delete_key(picowal_db_t* db, uint32_t key);

/* >=0 byte count on success; -1 on failure with errno set. */
int picowal_db_get_key(picowal_db_t* db, uint32_t key, void* out, uint32_t out_len);
bool picowal_db_exists_key(picowal_db_t* db, uint32_t key);
uint32_t picowal_db_list_records(picowal_db_t* db, uint16_t card,
                                 uint32_t* out_records, uint32_t max_records);

/* Monotonically increasing counter bumped on every write to pack 1 (pack-
 * name registry) or pack 2 (schema store). picowal_query.c uses this to
 * cheaply invalidate its parsed-query cache when schema/pack metadata
 * changes, without needing to track individual pack dependencies. */
uint64_t picowal_db_schema_generation(picowal_db_t* db);

/* --- Checkpointing ---
 * Folds every SEALED WAL segment's live (committed, non-tombstone,
 * latest-version) records into a freshly rewritten base.dat (atomic
 * temp+rename), then deletes those now-fully-applied WAL segment files.
 * The leading WAL segment is never touched -- only sealed ones are
 * checkpoint candidates. Returns 0 on success (with
 * out_bytes_reclaimed / out_segments_removed populated if non-NULL,
 * both 0 if nothing was eligible) or -1 on failure (errno set; EROFS if
 * read-only). Safe to call concurrently with reads/writes/transactions
 * (briefly holds the same db-wide lock). */
int picowal_db_checkpoint(picowal_db_t* db, uint64_t* out_bytes_reclaimed,
                          uint32_t* out_segments_removed);

/* Spawns a detached background thread (idempotent) that periodically
 * calls picowal_db_checkpoint() once enough sealed-WAL bytes are
 * reclaimable, and a second detached background flusher thread that
 * opportunistically fdatasync()s the leading WAL segment for pending
 * PICOWAL_DURABILITY_FIRE_AND_FORGET commits. Both no-op while read-only
 * (a replica mirrors the primary's base.dat/WAL directly). */
void picowal_db_start_background_threads(picowal_db_t* db);

void picowal_db_usage_stats(picowal_db_t* db, uint64_t* out_wal_bytes,
                            uint64_t* out_live_bytes, uint32_t* out_live_records);
const char* picowal_db_path(picowal_db_t* db);
uint64_t picowal_db_segment_bytes(picowal_db_t* db);

/* --- Replication primitives ---
 * base.dat and each WAL segment replicate independently: base.dat is
 * fetched wholesale whenever its generation changes (i.e. a checkpoint
 * just folded more WAL into it) or a replica doesn't have it yet; sealed
 * WAL segments are fetched wholesale once, exactly like base.dat; the
 * leading WAL segment is followed incrementally via byte-range
 * streaming, same as before. A checkpoint on the primary therefore only
 * ever costs a replica one base.dat re-fetch plus dropping the WAL
 * segments that got removed -- it never has to touch the (possibly much
 * larger, and still actively growing) leading segment. See
 * picowal_repl.h for the wire protocol. */

typedef struct {
    uint32_t seg_id;      /* 0 reserved for base.dat; WAL segments are 1.. */
    uint32_t generation;
    bool     sealed;      /* always true for base.dat; false only for the
                             current leading WAL segment */
    uint64_t bytes;        /* valid content bytes (excludes the header sector);
                             for the leading segment this is its current
                             write offset */
} picowal_seg_info_t;

#define PICOWAL_BASE_SEG_ID 0u

void picowal_db_repl_status(picowal_db_t* db, uint32_t* out_leading_wal_id,
                            uint64_t* out_leading_write_off,
                            uint64_t* out_segment_bytes, uint64_t* out_next_seq);

uint32_t picowal_db_list_segments(picowal_db_t* db, picowal_seg_info_t* out, uint32_t max_out);

/* Reads the whole current content (header sector + all valid record
 * bytes) of base.dat or a SEALED WAL segment for whole-file replica
 * transfer. -1/ENOENT if seg_id doesn't exist; -1/EROFS if seg_id is the
 * current leading WAL segment (use repl_read_leading instead); -1/ESTALE
 * if generation != want_generation (a compaction/checkpoint raced --
 * caller should re-list segments and retry). */
int picowal_db_repl_read_segment(picowal_db_t* db, uint32_t seg_id, uint32_t want_generation,
                                 void* out, uint32_t* inout_len);

/* Reads raw bytes [from_off, from_off+*inout_len) from the CURRENT
 * leading WAL segment only. -1/EINVAL if seg_id isn't the current
 * leading id (it just got sealed by rotation -- fetch it wholesale via
 * repl_read_segment instead and start following the new leading id from
 * offset 0). */
int picowal_db_repl_read_leading(picowal_db_t* db, uint32_t seg_id, uint64_t from_off,
                                 void* out, uint32_t* inout_len);

/* Replica side: installs/replaces base.dat or a sealed WAL segment
 * wholesale from data obtained via picowal_db_repl_read_segment().
 * Validates the embedded header, writes via temp+rename, and replays its
 * committed records into the index (first dropping any local index
 * entries that pointed at the old generation of the same seg_id). */
int picowal_db_repl_install_segment(picowal_db_t* db, uint32_t seg_id, uint32_t generation,
                                    const void* data, uint32_t len);

/* Replica side: appends bytes received from the primary's leading WAL
 * segment at the exact offset this db believes that segment's write_off
 * to be (EINVAL on gap/overlap), then replays the newly-written span
 * (honoring transaction commit-marker framing exactly like local
 * recovery) to extend the index and advance write_off/next_seq. An
 * unrecognized seg_id is treated as a brand new leading segment starting
 * at offset 0 (adopting a freshly-rotated leading segment needs no
 * separate "create" step). */
int picowal_db_repl_ingest_segment(picowal_db_t* db, uint32_t seg_id, uint64_t at_off,
                                   const void* data, uint32_t len);

/* Replica side: the primary's segment list no longer contains seg_id
 * (checkpoint deleted it) -- deletes the local copy too. 0 on success
 * (including if it didn't exist locally); -1 on failure. */
int picowal_db_repl_drop_segment(picowal_db_t* db, uint32_t seg_id);

/* --- Replication ack registry (primary side), for
 * PICOWAL_DURABILITY_REPLICATED commits ---
 * A replica calls this (via picowal_repl.c's ack endpoint) after every
 * successful ingest to report "I've applied up through this offset of
 * this leading-WAL seg_id". picowal_db_txn_commit()/put_key_dur() with
 * REPLICATED durability polls this registry (bounded by
 * PICOWAL_REPL_ACK_TIMEOUT_MS) waiting for a quorum -- by default
 * "quorum" is simply ">=1 registered replica has acked", since this
 * engine has no fixed follower-set concept of its own (picowal_gossip.c
 * layers that on top); set a minimum via
 * picowal_db_repl_ack_set_quorum() if you want a stricter bar. */
void picowal_db_repl_ack(picowal_db_t* db, const char* replica_id,
                         uint32_t seg_id, uint64_t offset);
void picowal_db_repl_ack_set_quorum(picowal_db_t* db, uint32_t min_replica_acks);
void picowal_db_repl_ack_register(picowal_db_t* db, const char* replica_id);

#endif
