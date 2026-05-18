#include "picowal_validate.h"

#include <ctype.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PWV_PACK_USERS   0U
#define PWV_PACK_NAMES   1U
#define PWV_PACK_SCHEMA  2U

#define PWV_MAX_FIELDS        64
#define PWV_MAX_TOKEN_LEN     96
#define PWV_MAX_VALUE_LEN     512
#define PWV_MAX_SCHEMA_LEN    (PICOWAL_DATA_MAX + 1)
#define PWV_MAX_RECORDS_SCAN  4096U

typedef enum {
    JV_NONE = 0,
    JV_STRING,
    JV_NUMBER,
    JV_BOOL,
    JV_NULL,
    JV_OBJECT,
    JV_ARRAY,
} jv_kind_t;

typedef struct {
    char key[PWV_MAX_TOKEN_LEN];
    jv_kind_t kind;
    char text[PWV_MAX_VALUE_LEN];
} jfield_t;

typedef struct {
    jfield_t items[PWV_MAX_FIELDS];
    size_t count;
} jobject_t;

typedef struct {
    char field[PWV_MAX_TOKEN_LEN];
    char value[PWV_MAX_VALUE_LEN];
} kv_map_t;

typedef struct {
    uint16_t target_pack;
    char fk_field[PWV_MAX_TOKEN_LEN];
} join_map_t;

static void set_err(char* err, size_t cap, const char* msg) {
    if (!err || cap == 0) return;
    snprintf(err, cap, "%s", msg ? msg : "validation failed");
}

static void trim_inplace(char* s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    size_t i = 0;
    while (s[i] && isspace((unsigned char)s[i])) i++;
    if (i > 0) memmove(s, s + i, strlen(s + i) + 1);
}

static const char* skip_ws(const char* p) {
    while (p && *p && isspace((unsigned char)*p)) p++;
    return p;
}

static const char* skip_json_string(const char* p) {
    if (!p || *p != '"') return p;
    p++;
    while (*p) {
        if (*p == '\\' && p[1]) {
            p += 2;
            continue;
        }
        if (*p == '"') return p + 1;
        p++;
    }
    return p;
}

static const char* skip_json_value(const char* p) {
    p = skip_ws(p);
    if (!p || !*p) return p;
    if (*p == '"') return skip_json_string(p);
    if (*p == '{' || *p == '[') {
        char open = *p;
        char close = (open == '{') ? '}' : ']';
        int depth = 0;
        while (*p) {
            if (*p == '"') {
                p = skip_json_string(p);
                continue;
            }
            if (*p == open) depth++;
            else if (*p == close) {
                depth--;
                if (depth == 0) return p + 1;
            }
            p++;
        }
        return p;
    }
    while (*p && *p != ',' && *p != '}' && *p != ']' && !isspace((unsigned char)*p)) p++;
    return p;
}

static bool parse_json_string(const char** pp, char* out, size_t cap) {
    const char* p = *pp;
    if (!p || *p != '"' || !out || cap < 2) return false;
    p++;
    size_t n = 0;
    while (*p && *p != '"') {
        unsigned char ch = (unsigned char)*p;
        if (ch == '\\') {
            p++;
            if (!*p) return false;
            switch (*p) {
            case '"': ch = '"'; break;
            case '\\': ch = '\\'; break;
            case '/': ch = '/'; break;
            case 'b': ch = '\b'; break;
            case 'f': ch = '\f'; break;
            case 'n': ch = '\n'; break;
            case 'r': ch = '\r'; break;
            case 't': ch = '\t'; break;
            default: ch = (unsigned char)*p; break;
            }
        }
        if (n + 1 >= cap) return false;
        out[n++] = (char)ch;
        p++;
    }
    if (*p != '"') return false;
    out[n] = '\0';
    *pp = p + 1;
    return true;
}

static bool parse_json_number(const char** pp, char* out, size_t cap) {
    const char* p = *pp;
    if (!p || !*p || !out || cap < 2) return false;
    size_t n = 0;
    if (*p == '-' || *p == '+') {
        if (n + 1 >= cap) return false;
        out[n++] = *p++;
    }
    while (*p && *p != ',' && *p != '}' && *p != ']' && !isspace((unsigned char)*p)) {
        if (n + 1 >= cap) return false;
        out[n++] = *p++;
    }
    if (n == 0 || (n == 1 && (out[0] == '-' || out[0] == '+'))) return false;
    out[n] = '\0';
    *pp = p;
    return true;
}

static bool parse_json_object(const char* json, jobject_t* out) {
    if (!json || !out) return false;
    memset(out, 0, sizeof(*out));
    const char* p = skip_ws(json);
    if (*p != '{') return false;
    p++;
    for (;;) {
        p = skip_ws(p);
        if (*p == '}') return true;
        if (*p != '"' || out->count >= PWV_MAX_FIELDS) return false;

        jfield_t* f = &out->items[out->count];
        if (!parse_json_string(&p, f->key, sizeof(f->key))) return false;
        p = skip_ws(p);
        if (*p != ':') return false;
        p++;
        p = skip_ws(p);
        if (!*p) return false;

        if (*p == '"') {
            f->kind = JV_STRING;
            if (!parse_json_string(&p, f->text, sizeof(f->text))) return false;
        } else if (strncmp(p, "true", 4) == 0) {
            f->kind = JV_BOOL;
            snprintf(f->text, sizeof(f->text), "true");
            p += 4;
        } else if (strncmp(p, "false", 5) == 0) {
            f->kind = JV_BOOL;
            snprintf(f->text, sizeof(f->text), "false");
            p += 5;
        } else if (strncmp(p, "null", 4) == 0) {
            f->kind = JV_NULL;
            snprintf(f->text, sizeof(f->text), "null");
            p += 4;
        } else if (*p == '{') {
            const char* e = skip_json_value(p);
            if (!e || e == p) return false;
            f->kind = JV_OBJECT;
            f->text[0] = '\0';
            p = e;
        } else if (*p == '[') {
            const char* e = skip_json_value(p);
            if (!e || e == p) return false;
            f->kind = JV_ARRAY;
            f->text[0] = '\0';
            p = e;
        } else {
            f->kind = JV_NUMBER;
            if (!parse_json_number(&p, f->text, sizeof(f->text))) return false;
        }

        out->count++;
        p = skip_ws(p);
        if (*p == ',') {
            p++;
            continue;
        }
        if (*p == '}') return true;
        return false;
    }
}

static const jfield_t* json_object_get(const jobject_t* obj, const char* key) {
    if (!obj || !key || !*key) return NULL;
    for (size_t i = 0; i < obj->count; i++) {
        if (strcmp(obj->items[i].key, key) == 0) return &obj->items[i];
    }
    return NULL;
}

static bool parse_u16_dec(const char* s, uint16_t max, uint16_t* out) {
    if (!s || !*s || !out) return false;
    uint32_t v = 0;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        v = v * 10u + (uint32_t)(*p - '0');
        if (v > max) return false;
    }
    *out = (uint16_t)v;
    return true;
}

static bool parse_u32_dec(const char* s, uint32_t max, uint32_t* out) {
    if (!s || !*s || !out) return false;
    uint64_t v = 0;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        v = v * 10u + (uint64_t)(*p - '0');
        if (v > max) return false;
    }
    *out = (uint32_t)v;
    return true;
}

static bool is_system_pack(uint16_t pack_id) {
    return pack_id == PWV_PACK_USERS || pack_id == PWV_PACK_NAMES || pack_id == PWV_PACK_SCHEMA;
}

static bool load_record_json(picowal_db_t* db, uint16_t pack_id, uint32_t record_id,
                             char* out, size_t out_cap) {
    if (!db || !out || out_cap < 2) return false;
    uint32_t key = 0;
    if (!picowal_db_pack_key(pack_id, record_id, &key)) return false;
    int n = picowal_db_get_key(db, key, out, (uint32_t)(out_cap - 1));
    if (n < 0) return false;
    out[n] = '\0';
    return true;
}

static size_t parse_csv_list(const char* csv, char out[][PWV_MAX_TOKEN_LEN], size_t max_items) {
    if (!csv || !*csv || !out || max_items == 0) return 0;
    char tmp[PWV_MAX_SCHEMA_LEN];
    snprintf(tmp, sizeof(tmp), "%s", csv);
    size_t n = 0;
    char* save = NULL;
    for (char* tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        trim_inplace(tok);
        if (!tok[0]) continue;
        if (n >= max_items) break;
        snprintf(out[n], PWV_MAX_TOKEN_LEN, "%s", tok);
        n++;
    }
    return n;
}

static bool list_has_token(char list[][PWV_MAX_TOKEN_LEN], size_t n, const char* token) {
    if (!token || !*token) return false;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(list[i], token) == 0) return true;
    }
    return false;
}

static size_t parse_assign_map(const char* text, kv_map_t* out, size_t max_items) {
    if (!text || !*text || !out || max_items == 0) return 0;
    char tmp[PWV_MAX_SCHEMA_LEN];
    snprintf(tmp, sizeof(tmp), "%s", text);
    size_t n = 0;
    char* save = NULL;
    for (char* tok = strtok_r(tmp, ";", &save); tok; tok = strtok_r(NULL, ";", &save)) {
        trim_inplace(tok);
        if (!tok[0]) continue;
        char* sep = strchr(tok, '=');
        if (!sep) sep = strchr(tok, ':');
        if (!sep) continue;
        *sep = '\0';
        char* k = tok;
        char* v = sep + 1;
        trim_inplace(k);
        trim_inplace(v);
        if (!k[0] || !v[0]) continue;
        if (n >= max_items) break;
        snprintf(out[n].field, sizeof(out[n].field), "%s", k);
        snprintf(out[n].value, sizeof(out[n].value), "%s", v);
        n++;
    }
    return n;
}

static size_t parse_joins_map(const char* csv, join_map_t* out, size_t max_items) {
    if (!csv || !*csv || !out || max_items == 0) return 0;
    char tmp[PWV_MAX_SCHEMA_LEN];
    snprintf(tmp, sizeof(tmp), "%s", csv);
    size_t n = 0;
    char* save = NULL;
    for (char* tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        trim_inplace(tok);
        if (!tok[0]) continue;
        char* sep = strchr(tok, '=');
        if (!sep) sep = strchr(tok, ':');
        if (!sep) continue;
        *sep = '\0';
        char* p = tok;
        char* f = sep + 1;
        trim_inplace(p);
        trim_inplace(f);
        uint16_t target = 0;
        if (!parse_u16_dec(p, PICOWAL_CARD_MAX, &target)) continue;
        if (!f[0]) continue;
        if (n >= max_items) break;
        out[n].target_pack = target;
        snprintf(out[n].fk_field, sizeof(out[n].fk_field), "%s", f);
        n++;
    }
    return n;
}

static bool is_email_like(const char* s) {
    if (!s || !*s) return false;
    const char* at = strchr(s, '@');
    if (!at || at == s || at[1] == '\0') return false;
    if (strchr(at + 1, '@') != NULL) return false;
    const char* dot = strchr(at + 1, '.');
    if (!dot || dot == at + 1 || dot[1] == '\0') return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        if (isspace(*p)) return false;
    }
    return true;
}

static bool parse_number_record_id(const jfield_t* f, uint32_t* out_record) {
    if (!f || !out_record || f->kind != JV_NUMBER) return false;
    return parse_u32_dec(f->text, PICOWAL_RECORD_MAX, out_record);
}

static bool validate_field_types(const jobject_t* body_obj,
                                 const kv_map_t* types, size_t types_n,
                                 int* out_http_status, char* err, size_t err_cap) {
    for (size_t i = 0; i < types_n; i++) {
        const jfield_t* f = json_object_get(body_obj, types[i].field);
        if (!f) continue;

        char expect[PWV_MAX_TOKEN_LEN];
        snprintf(expect, sizeof(expect), "%s", types[i].value);
        trim_inplace(expect);
        bool allow_null = false;
        size_t elen = strlen(expect);
        if (elen > 1 && expect[elen - 1] == '?') {
            allow_null = true;
            expect[elen - 1] = '\0';
        }

        if (f->kind == JV_NULL && allow_null) continue;

        bool ok = false;
        if (strcmp(expect, "string") == 0) ok = (f->kind == JV_STRING);
        else if (strcmp(expect, "number") == 0 || strcmp(expect, "integer") == 0) ok = (f->kind == JV_NUMBER);
        else if (strcmp(expect, "bool") == 0 || strcmp(expect, "boolean") == 0) ok = (f->kind == JV_BOOL);
        else if (strcmp(expect, "object") == 0) ok = (f->kind == JV_OBJECT);
        else if (strcmp(expect, "array") == 0) ok = (f->kind == JV_ARRAY);
        else {
            if (out_http_status) *out_http_status = 500;
            set_err(err, err_cap, "schema has unsupported type");
            return false;
        }
        if (!ok) {
            if (out_http_status) *out_http_status = 400;
            set_err(err, err_cap, "field type mismatch");
            return false;
        }
    }
    return true;
}

static bool validate_join_refs(picowal_db_t* db, const jobject_t* body_obj,
                               const join_map_t* joins, size_t joins_n,
                               int* out_http_status, char* err, size_t err_cap) {
    for (size_t i = 0; i < joins_n; i++) {
        const jfield_t* fk = json_object_get(body_obj, joins[i].fk_field);
        if (!fk || fk->kind == JV_NULL) continue;
        uint32_t ref_record = 0;
        if (!parse_number_record_id(fk, &ref_record)) {
            if (out_http_status) *out_http_status = 400;
            set_err(err, err_cap, "lookup field must be numeric");
            return false;
        }
        uint32_t ref_key = 0;
        if (!picowal_db_pack_key(joins[i].target_pack, ref_record, &ref_key)) {
            if (out_http_status) *out_http_status = 400;
            set_err(err, err_cap, "invalid lookup target");
            return false;
        }
        if (!picowal_db_exists_key(db, ref_key)) {
            if (out_http_status) *out_http_status = 409;
            set_err(err, err_cap, "lookup value does not exist");
            return false;
        }
    }
    return true;
}

static bool transition_allowed(const char* mapping, const char* from, const char* to) {
    if (!mapping || !from || !to) return false;
    char tmp[PWV_MAX_SCHEMA_LEN];
    snprintf(tmp, sizeof(tmp), "%s", mapping);
    char* save = NULL;
    for (char* tok = strtok_r(tmp, "|", &save); tok; tok = strtok_r(NULL, "|", &save)) {
        trim_inplace(tok);
        if (!tok[0]) continue;
        char* sep = strchr(tok, '>');
        if (!sep) continue;
        *sep = '\0';
        char* a = tok;
        char* b = sep + 1;
        trim_inplace(a);
        trim_inplace(b);
        if (strcmp(a, from) == 0 && strcmp(b, to) == 0) return true;
    }
    return false;
}

static bool validate_transitions(picowal_db_t* db, uint16_t pack_id, uint32_t record_id,
                                 const jobject_t* new_obj, const kv_map_t* transitions,
                                 size_t transitions_n, int* out_http_status,
                                 char* err, size_t err_cap) {
    if (record_id > PICOWAL_RECORD_MAX || transitions_n == 0) return true;

    char old_json[PWV_MAX_SCHEMA_LEN];
    if (!load_record_json(db, pack_id, record_id, old_json, sizeof(old_json))) return true;
    jobject_t old_obj;
    if (!parse_json_object(old_json, &old_obj)) return true;

    for (size_t i = 0; i < transitions_n; i++) {
        const jfield_t* oldf = json_object_get(&old_obj, transitions[i].field);
        const jfield_t* newf = json_object_get(new_obj, transitions[i].field);
        if (!oldf || !newf) continue;
        if (oldf->kind == JV_NULL || newf->kind == JV_NULL) continue;
        if (oldf->kind != JV_STRING || newf->kind != JV_STRING) {
            if (out_http_status) *out_http_status = 400;
            set_err(err, err_cap, "transition fields must be strings");
            return false;
        }
        if (strcmp(oldf->text, newf->text) == 0) continue;
        if (!transition_allowed(transitions[i].value, oldf->text, newf->text)) {
            if (out_http_status) *out_http_status = 409;
            set_err(err, err_cap, "transition not allowed");
            return false;
        }
    }
    return true;
}

static bool validate_regex_rules(const jobject_t* body_obj, const kv_map_t* regexes, size_t regex_n,
                                 int* out_http_status, char* err, size_t err_cap) {
    for (size_t i = 0; i < regex_n; i++) {
        const jfield_t* f = json_object_get(body_obj, regexes[i].field);
        if (!f || f->kind == JV_NULL) continue;
        if (f->kind != JV_STRING) {
            if (out_http_status) *out_http_status = 400;
            set_err(err, err_cap, "regex field must be string");
            return false;
        }
        regex_t re;
        int rc = regcomp(&re, regexes[i].value, REG_EXTENDED | REG_NOSUB);
        if (rc != 0) {
            if (out_http_status) *out_http_status = 500;
            set_err(err, err_cap, "invalid regex in schema");
            return false;
        }
        rc = regexec(&re, f->text, 0, NULL, 0);
        regfree(&re);
        if (rc != 0) {
            if (out_http_status) *out_http_status = 400;
            set_err(err, err_cap, "regex validation failed");
            return false;
        }
    }
    return true;
}

static bool validate_write(picowal_db_t* db, uint16_t pack_id, uint32_t record_id,
                           const char* body, size_t body_len,
                           int* out_http_status, char* err, size_t err_cap) {
    if (!body || body_len == 0 || body_len > PICOWAL_DATA_MAX) {
        if (out_http_status) *out_http_status = 400;
        set_err(err, err_cap, "request body required");
        return false;
    }

    char payload[PWV_MAX_SCHEMA_LEN];
    memcpy(payload, body, body_len);
    payload[body_len] = '\0';

    jobject_t body_obj;
    if (!parse_json_object(payload, &body_obj)) {
        if (out_http_status) *out_http_status = 400;
        set_err(err, err_cap, "body must be a JSON object");
        return false;
    }

    char schema_json[PWV_MAX_SCHEMA_LEN];
    if (!load_record_json(db, PWV_PACK_SCHEMA, pack_id, schema_json, sizeof(schema_json))) {
        return true; /* no schema = no-op validation */
    }
    jobject_t schema_obj;
    if (!parse_json_object(schema_json, &schema_obj)) {
        if (out_http_status) *out_http_status = 500;
        set_err(err, err_cap, "schema document is invalid");
        return false;
    }

    const jfield_t* f_fields = json_object_get(&schema_obj, "fields");
    if (!f_fields || f_fields->kind != JV_STRING || !f_fields->text[0]) return true;

    char allowed[PWV_MAX_FIELDS][PWV_MAX_TOKEN_LEN];
    size_t allowed_n = parse_csv_list(f_fields->text, allowed, PWV_MAX_FIELDS);
    if (allowed_n == 0) return true;

    for (size_t i = 0; i < body_obj.count; i++) {
        if (!list_has_token(allowed, allowed_n, body_obj.items[i].key)) {
            if (out_http_status) *out_http_status = 400;
            set_err(err, err_cap, "field not defined in schema");
            return false;
        }
    }

    const jfield_t* f_required = json_object_get(&schema_obj, "required");
    if (f_required && f_required->kind == JV_STRING && f_required->text[0]) {
        char req[PWV_MAX_FIELDS][PWV_MAX_TOKEN_LEN];
        size_t req_n = parse_csv_list(f_required->text, req, PWV_MAX_FIELDS);
        for (size_t i = 0; i < req_n; i++) {
            const jfield_t* rf = json_object_get(&body_obj, req[i]);
            if (!rf || rf->kind == JV_NULL || (rf->kind == JV_STRING && rf->text[0] == '\0')) {
                if (out_http_status) *out_http_status = 400;
                set_err(err, err_cap, "required field missing");
                return false;
            }
        }
    }

    const jfield_t* f_types = json_object_get(&schema_obj, "types");
    if (f_types && f_types->kind == JV_STRING && f_types->text[0]) {
        kv_map_t types[PWV_MAX_FIELDS];
        size_t types_n = parse_assign_map(f_types->text, types, PWV_MAX_FIELDS);
        if (!validate_field_types(&body_obj, types, types_n, out_http_status, err, err_cap)) return false;
    }

    const jfield_t* f_email = json_object_get(&schema_obj, "email");
    if (f_email && f_email->kind == JV_STRING && f_email->text[0]) {
        char emails[PWV_MAX_FIELDS][PWV_MAX_TOKEN_LEN];
        size_t email_n = parse_csv_list(f_email->text, emails, PWV_MAX_FIELDS);
        for (size_t i = 0; i < email_n; i++) {
            const jfield_t* ef = json_object_get(&body_obj, emails[i]);
            if (!ef || ef->kind == JV_NULL) continue;
            if (ef->kind != JV_STRING || !is_email_like(ef->text)) {
                if (out_http_status) *out_http_status = 400;
                set_err(err, err_cap, "email validation failed");
                return false;
            }
        }
    }

    const jfield_t* f_regex = json_object_get(&schema_obj, "regex");
    if (f_regex && f_regex->kind == JV_STRING && f_regex->text[0]) {
        kv_map_t regexes[PWV_MAX_FIELDS];
        size_t regex_n = parse_assign_map(f_regex->text, regexes, PWV_MAX_FIELDS);
        if (!validate_regex_rules(&body_obj, regexes, regex_n, out_http_status, err, err_cap)) return false;
    }

    const jfield_t* f_joins = json_object_get(&schema_obj, "joins");
    if (f_joins && f_joins->kind == JV_STRING && f_joins->text[0]) {
        join_map_t joins[PWV_MAX_FIELDS];
        size_t joins_n = parse_joins_map(f_joins->text, joins, PWV_MAX_FIELDS);
        if (!validate_join_refs(db, &body_obj, joins, joins_n, out_http_status, err, err_cap)) return false;
    }

    const jfield_t* f_transitions = json_object_get(&schema_obj, "transitions");
    if (f_transitions && f_transitions->kind == JV_STRING && f_transitions->text[0]) {
        kv_map_t transitions[PWV_MAX_FIELDS];
        size_t t_n = parse_assign_map(f_transitions->text, transitions, PWV_MAX_FIELDS);
        if (!validate_transitions(db, pack_id, record_id, &body_obj, transitions, t_n,
                                  out_http_status, err, err_cap)) return false;
    }

    return true;
}

static bool validate_delete_refs(picowal_db_t* db, uint16_t pack_id, uint32_t record_id,
                                 int* out_http_status, char* err, size_t err_cap) {
    uint32_t schema_records[PWV_MAX_RECORDS_SCAN];
    uint32_t sn = picowal_db_list_records(db, PWV_PACK_SCHEMA, schema_records, PWV_MAX_RECORDS_SCAN);
    for (uint32_t i = 0; i < sn; i++) {
        uint32_t child_pack_u32 = schema_records[i];
        if (child_pack_u32 > PICOWAL_CARD_MAX) continue;
        uint16_t child_pack = (uint16_t)child_pack_u32;
        if (is_system_pack(child_pack)) continue;

        char schema_json[PWV_MAX_SCHEMA_LEN];
        if (!load_record_json(db, PWV_PACK_SCHEMA, child_pack, schema_json, sizeof(schema_json))) continue;
        jobject_t schema_obj;
        if (!parse_json_object(schema_json, &schema_obj)) continue;
        const jfield_t* f_joins = json_object_get(&schema_obj, "joins");
        if (!f_joins || f_joins->kind != JV_STRING || !f_joins->text[0]) continue;

        join_map_t joins[PWV_MAX_FIELDS];
        size_t joins_n = parse_joins_map(f_joins->text, joins, PWV_MAX_FIELDS);
        for (size_t j = 0; j < joins_n; j++) {
            if (joins[j].target_pack != pack_id) continue;

            uint32_t child_records[PWV_MAX_RECORDS_SCAN];
            uint32_t cn = picowal_db_list_records(db, child_pack, child_records, PWV_MAX_RECORDS_SCAN);
            for (uint32_t k = 0; k < cn; k++) {
                char child_json[PWV_MAX_SCHEMA_LEN];
                if (!load_record_json(db, child_pack, child_records[k], child_json, sizeof(child_json))) continue;
                jobject_t child_obj;
                if (!parse_json_object(child_json, &child_obj)) continue;
                const jfield_t* fk = json_object_get(&child_obj, joins[j].fk_field);
                if (!fk) continue;
                uint32_t ref = 0;
                if (!parse_number_record_id(fk, &ref)) continue;
                if (ref == record_id) {
                    if (out_http_status) *out_http_status = 409;
                    set_err(err, err_cap, "delete blocked by referential integrity");
                    return false;
                }
            }
        }
    }
    return true;
}

bool picowal_validate_mutation(picowal_db_t* db,
                               uint16_t pack_id,
                               uint32_t record_id,
                               picowal_validate_op_t op,
                               const char* body,
                               size_t body_len,
                               int* out_http_status,
                               char* err,
                               size_t err_cap) {
    if (out_http_status) *out_http_status = 400;
    if (!db) {
        if (out_http_status) *out_http_status = 500;
        set_err(err, err_cap, "validator unavailable");
        return false;
    }
    if (is_system_pack(pack_id)) return true;

    switch (op) {
    case PWV_OP_PUT:
    case PWV_OP_POST:
        return validate_write(db, pack_id, record_id, body, body_len, out_http_status, err, err_cap);
    case PWV_OP_DELETE:
        return validate_delete_refs(db, pack_id, record_id, out_http_status, err, err_cap);
    default:
        if (out_http_status) *out_http_status = 500;
        set_err(err, err_cap, "validator operation unsupported");
        return false;
    }
}
