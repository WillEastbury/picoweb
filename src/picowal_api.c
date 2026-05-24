#include "picowal_api.h"

#include <errno.h>
#include <sys/random.h>

picowal_api_status_t picowal_api_put(picowal_db_t* db, uint16_t card, uint32_t record,
                                      const void* data, uint32_t len, bool create_only) {
    if (!db || !data || card > PICOWAL_CARD_MAX ||
        record > PICOWAL_RECORD_MAX || len > PICOWAL_DATA_MAX) {
        return PICOWAL_API_INVALID;
    }
    uint32_t key = 0;
    if (!picowal_db_pack_key(card, record, &key)) return PICOWAL_API_INVALID;
    if (picowal_db_put_key(db, key, data, len, create_only) == 0) return PICOWAL_API_OK;
    if (errno == EEXIST) return PICOWAL_API_EXISTS;
    return PICOWAL_API_IO;
}

picowal_api_status_t picowal_api_get(picowal_db_t* db, uint16_t card, uint32_t record,
                                      void* out, uint32_t out_len, uint32_t* out_len_got) {
    if (out_len_got) *out_len_got = 0;
    if (!db || !out || card > PICOWAL_CARD_MAX || record > PICOWAL_RECORD_MAX) {
        return PICOWAL_API_INVALID;
    }
    uint32_t key = 0;
    if (!picowal_db_pack_key(card, record, &key)) return PICOWAL_API_INVALID;
    int got = picowal_db_get_key(db, key, out, out_len);
    if (got >= 0) {
        if (out_len_got) *out_len_got = (uint32_t)got;
        return PICOWAL_API_OK;
    }
    if (errno == ENOENT) return PICOWAL_API_NOT_FOUND;
    return PICOWAL_API_IO;
}

picowal_api_status_t picowal_api_delete(picowal_db_t* db, uint16_t card, uint32_t record) {
    if (!db || card > PICOWAL_CARD_MAX || record > PICOWAL_RECORD_MAX) {
        return PICOWAL_API_INVALID;
    }
    uint32_t key = 0;
    if (!picowal_db_pack_key(card, record, &key)) return PICOWAL_API_INVALID;
    if (picowal_db_delete_key(db, key) == 0) return PICOWAL_API_OK;
    if (errno == ENOENT) return PICOWAL_API_NOT_FOUND;
    return PICOWAL_API_IO;
}

picowal_api_status_t picowal_api_create_random(picowal_db_t* db, uint16_t card,
                                                const void* data, uint32_t len,
                                                uint32_t* out_record) {
    if (out_record) *out_record = 0;
    if (!db || !data || !out_record || card > PICOWAL_CARD_MAX || len > PICOWAL_DATA_MAX) {
        return PICOWAL_API_INVALID;
    }
    for (int attempt = 0; attempt < 16; attempt++) {
        uint32_t record = 0;
        if (getrandom(&record, sizeof(record), 0) != (ssize_t)sizeof(record)) {
            return PICOWAL_API_IO;
        }
        record %= (PICOWAL_RECORD_MAX + 1U);
        picowal_api_status_t st = picowal_api_put(db, card, record, data, len, true);
        if (st == PICOWAL_API_OK) {
            *out_record = record;
            return st;
        }
        if (st != PICOWAL_API_EXISTS) return st;
    }
    return PICOWAL_API_EXISTS;
}

uint32_t picowal_api_list(picowal_db_t* db, uint16_t card,
                          uint32_t* out_records, uint32_t max_records) {
    if (!db || !out_records || card > PICOWAL_CARD_MAX) return 0;
    return picowal_db_list_records(db, card, out_records, max_records);
}
