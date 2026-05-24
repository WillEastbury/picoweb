#ifndef PICOWAL_DB_H
#define PICOWAL_DB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PICOWAL_CARD_MAX            1023U
#define PICOWAL_RECORD_MAX          4194303U
#define PICOWAL_DATA_MAX            4096U
#define PICOWAL_DEFAULT_VOLUME_BYTES (1ULL << 30) /* 1 GiB */

typedef struct picowal_db picowal_db_t;

picowal_db_t* picowal_db_create(void);
void picowal_db_destroy(picowal_db_t* db);

bool picowal_db_pack_key(uint16_t card, uint32_t record, uint32_t* out_key);
void picowal_db_unpack_key(uint32_t key, uint16_t* card_out, uint32_t* record_out);

bool picowal_db_open(picowal_db_t* db, const char* device_path,
                     uint64_t volume_bytes, bool format);
void picowal_db_close(picowal_db_t* db);
bool picowal_db_healthy(picowal_db_t* db);

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
