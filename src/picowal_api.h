#ifndef PICOWAL_API_H
#define PICOWAL_API_H

#include "picowal_db.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    PICOWAL_API_OK = 0,
    PICOWAL_API_NOT_FOUND,
    PICOWAL_API_EXISTS,
    PICOWAL_API_INVALID,
    PICOWAL_API_IO,
} picowal_api_status_t;

picowal_api_status_t picowal_api_put(picowal_db_t* db, uint16_t card, uint32_t record,
                                      const void* data, uint32_t len, bool create_only);
picowal_api_status_t picowal_api_get(picowal_db_t* db, uint16_t card, uint32_t record,
                                      void* out, uint32_t out_len, uint32_t* out_len_got);
picowal_api_status_t picowal_api_delete(picowal_db_t* db, uint16_t card, uint32_t record);
picowal_api_status_t picowal_api_create_random(picowal_db_t* db, uint16_t card,
                                                const void* data, uint32_t len,
                                                uint32_t* out_record);
uint32_t picowal_api_list(picowal_db_t* db, uint16_t card,
                          uint32_t* out_records, uint32_t max_records);

#endif
