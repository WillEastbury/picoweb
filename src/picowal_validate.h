#ifndef PICOWAL_VALIDATE_H
#define PICOWAL_VALIDATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "picowal_db.h"

typedef enum {
    PWV_OP_PUT = 0,
    PWV_OP_POST,
    PWV_OP_DELETE,
} picowal_validate_op_t;

bool picowal_validate_mutation(picowal_db_t* db,
                               uint16_t pack_id,
                               uint32_t record_id,
                               picowal_validate_op_t op,
                               const char* body,
                               size_t body_len,
                               int* out_http_status,
                               char* err,
                               size_t err_cap);

#endif
