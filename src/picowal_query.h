#ifndef PICOWAL_QUERY_H
#define PICOWAL_QUERY_H

#include <stdbool.h>
#include <stddef.h>

#include "picowal_db.h"

bool picowal_query_run(picowal_db_t* db, const char* text,
                       char** out_json, size_t* out_len,
                       char* err, size_t err_cap);

#endif
