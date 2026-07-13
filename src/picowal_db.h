#ifndef PICOWAL_DB_H
#define PICOWAL_DB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PICOWAL_CARD_MAX            1023U
#define PICOWAL_RECORD_MAX          4194303U
#define PICOWAL_DATA_MAX            4096U
#define PICOWAL_DEFAULT_VOLUME_BYTES (1ULL << 30) /* 1 GiB */
#define PICOWAL_REPL_CHUNK_MAX       (4U * 1024U * 1024U) /* max bytes per repl fetch */

/* On-disk header layout: two alternating 512-byte superblock slots
 * (sector 0 and sector 1), each carrying a generation counter, a cached
 * write_off/next_seq checkpoint, and a checksum. Every checkpoint write
 * goes to whichever slot is NOT the currently-active one and bumps the
 * generation; on open, whichever valid slot has the higher generation
 * wins. This makes a crash mid-checkpoint safe (the torn slot just fails
 * its own checksum and is ignored) without ever risking the *only* copy
 * of the metadata being half-written. Log data begins at sector 2. */
#define PICOWAL_SECTOR_BYTES         512ULL
#define PICOWAL_SB_SLOT_COUNT        2ULL
#define PICOWAL_DATA_START           (PICOWAL_SB_SLOT_COUNT * PICOWAL_SECTOR_BYTES)

typedef struct picowal_db picowal_db_t;

picowal_db_t* picowal_db_create(void);
void picowal_db_destroy(picowal_db_t* db);

bool picowal_db_pack_key(uint16_t card, uint32_t record, uint32_t* out_key);
void picowal_db_unpack_key(uint32_t key, uint16_t* card_out, uint32_t* record_out);

bool picowal_db_open(picowal_db_t* db, const char* device_path,
                     uint64_t volume_bytes, bool format);
void picowal_db_close(picowal_db_t* db);

/* Marks the volume read-only (or read-write again): used by replica-mode
 * nodes to refuse local mutations (picowal_db_put_key/delete_key return
 * -1/EROFS) while continuing to serve reads and ingest replicated bytes
 * via picowal_db_repl_ingest() (which bypasses this check -- that's the
 * one writer path a replica is allowed to use). */
void picowal_db_set_read_only(picowal_db_t* db, bool read_only);

/* --- Replication primitives ---
 * picowal's on-disk format is a sector-aligned, append-only log with a
 * two-slot alternating superblock (see PICOWAL_DATA_START above): every
 * mutation is a new record appended at write_off, never an in-place
 * rewrite. That makes raw byte-range streaming of [some_offset,
 * write_off) a complete, self-describing physical replication feed -- a
 * replica just needs to append those same bytes to its own copy of the
 * file and re-run the same record-parsing logic used at startup
 * (scan_volume) over the newly-appended span. write_off/next_seq are also
 * periodically checkpointed into the superblock so a replica's (or the
 * primary's) own reopen after a clean or unclean restart doesn't need to
 * rescan the whole log, only the tail since the last checkpoint. */

/* Thread-safe snapshot of current log position/generation, for a
 * replication primary to report to a replica. */
void picowal_db_repl_status(picowal_db_t* db, uint64_t* out_write_off,
                            uint64_t* out_volume_bytes, uint64_t* out_next_seq);

/* Read raw log bytes [from_off, from_off+*inout_len) directly off the
 * volume for streaming to a replica. from_off must be sector-aligned and
 * >= PICOWAL_SECTOR_SIZE (the superblock is never streamed -- a replica
 * formats its own on first connect). *inout_len is clamped to what's
 * actually available up to the current write_off before reading; the
 * clamped value is written back. 0 on success (possibly with *inout_len
 * reduced to 0 if the replica is already caught up); -1 on failure. */
int picowal_db_repl_read(picowal_db_t* db, uint64_t from_off,
                         void* out, uint32_t* inout_len);

/* Replica side: append raw log bytes received from the primary at the
 * exact offset the replica already believes write_off to be (rejects any
 * gap/overlap with EINVAL), then incrementally replays just the
 * newly-written span through the same validation scan_volume() uses
 * (magic/len/flags/checksum) to extend the in-memory index and advance
 * write_off/next_seq. Any record that fails validation stops the replay
 * at that point (matching crash-recovery semantics) and returns -1/EIO --
 * the replica should re-fetch from its last confirmed write_off. */
int picowal_db_repl_ingest(picowal_db_t* db, uint64_t at_off,
                           const void* data, uint32_t len);

/* 0 on success; -1 on failure with errno set. */
int picowal_db_put_key(picowal_db_t* db, uint32_t key,
                       const void* data, uint32_t len, bool create_only);
/* >=0 byte count on success; -1 on failure with errno set. */
int picowal_db_get_key(picowal_db_t* db, uint32_t key, void* out, uint32_t out_len);
/* 0 on success; -1 on failure with errno set. */
int picowal_db_delete_key(picowal_db_t* db, uint32_t key);
bool picowal_db_exists_key(picowal_db_t* db, uint32_t key);
uint32_t picowal_db_list_records(picowal_db_t* db, uint16_t card,
                                 uint32_t* out_records, uint32_t max_records);

#endif
