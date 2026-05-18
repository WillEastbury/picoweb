#include "picowal_query.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define PWQ_MAX_SELECT   16
#define PWQ_MAX_WHERE    8
#define PWQ_MAX_FROM     4
#define PWQ_MAX_RESULTS  100
#define PWQ_SCAN_LIMIT   4096

#define PWQ_PACK_USERS   0U
#define PWQ_PACK_NAMES   1U
#define PWQ_PACK_SCHEMA  2U

typedef enum {
    PWQ_OP_EQ = 0,
    PWQ_OP_NE,
    PWQ_OP_GT,
    PWQ_OP_LT,
    PWQ_OP_GE,
    PWQ_OP_LE,
    PWQ_OP_IN,
    PWQ_OP_NI,
} pwq_op_t;

typedef struct {
    char pack[32];
    char field[32];
    char label[64];
} pwq_select_t;

typedef struct {
    char pack[32];
    char field[32];
    pwq_op_t op;
    char value[64];
} pwq_where_t;

typedef struct {
    char from[PWQ_MAX_FROM][32];
    uint16_t from_ids[PWQ_MAX_FROM];
    uint8_t from_count;
    bool select_all;
    pwq_select_t select[PWQ_MAX_SELECT];
    uint8_t select_count;
    pwq_where_t where[PWQ_MAX_WHERE];
    uint8_t where_count;
} pwq_query_t;

typedef enum {
    JVAL_NONE = 0,
    JVAL_STRING,
    JVAL_NUMBER,
    JVAL_BOOL,
    JVAL_NULL
} jval_kind_t;

typedef struct {
    jval_kind_t kind;
    char text[256];
} jval_t;

typedef struct {
    char* data;
    size_t len;
    size_t cap;
} sb_t;

static void set_err(char* err, size_t cap, const char* msg) {
    if (!err || cap == 0) return;
    snprintf(err, cap, "%s", msg);
}

static bool sb_reserve(sb_t* sb, size_t extra) {
    if (sb->len + extra + 1 <= sb->cap) return true;
    size_t need = sb->len + extra + 1;
    size_t ncap = sb->cap ? sb->cap : 1024;
    while (ncap < need) ncap *= 2;
    char* p = (char*)realloc(sb->data, ncap);
    if (!p) return false;
    sb->data = p;
    sb->cap = ncap;
    return true;
}

static bool sb_append_raw(sb_t* sb, const char* s, size_t n) {
    if (!sb_reserve(sb, n)) return false;
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
    return true;
}

static bool sb_append(sb_t* sb, const char* s) {
    return sb_append_raw(sb, s, strlen(s));
}

static bool sb_append_ch(sb_t* sb, char c) {
    return sb_append_raw(sb, &c, 1);
}

static bool sb_append_json_string(sb_t* sb, const char* s) {
    if (!sb_append_ch(sb, '"')) return false;
    for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
        if (*p == '"' || *p == '\\') {
            if (!sb_append_ch(sb, '\\') || !sb_append_ch(sb, (char)*p)) return false;
        } else if (*p == '\n') {
            if (!sb_append(sb, "\\n")) return false;
        } else if (*p == '\r') {
            if (!sb_append(sb, "\\r")) return false;
        } else if (*p == '\t') {
            if (!sb_append(sb, "\\t")) return false;
        } else if (*p < 0x20) {
            char esc[8];
            int n = snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)*p);
            if (n <= 0 || !sb_append_raw(sb, esc, (size_t)n)) return false;
        } else {
            if (!sb_append_ch(sb, (char)*p)) return false;
        }
    }
    return sb_append_ch(sb, '"');
}

static void trim(char* s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    size_t i = 0;
    while (s[i] && isspace((unsigned char)s[i])) i++;
    if (i > 0) memmove(s, s + i, strlen(s + i) + 1);
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

static pwq_op_t parse_op(const char* s) {
    if (strcmp(s, "==") == 0) return PWQ_OP_EQ;
    if (strcmp(s, "!=") == 0) return PWQ_OP_NE;
    if (strcmp(s, ">") == 0) return PWQ_OP_GT;
    if (strcmp(s, "<") == 0) return PWQ_OP_LT;
    if (strcmp(s, ">=") == 0) return PWQ_OP_GE;
    if (strcmp(s, "<=") == 0) return PWQ_OP_LE;
    if (strcasecmp(s, "IN") == 0) return PWQ_OP_IN;
    if (strcasecmp(s, "NI") == 0) return PWQ_OP_NI;
    return PWQ_OP_EQ;
}

static void split_dotted(const char* in, char* pack, size_t pack_cap,
                         char* field, size_t field_cap) {
    const char* dot = strchr(in, '.');
    if (!dot) {
        pack[0] = '\0';
        snprintf(field, field_cap, "%s", in);
        return;
    }
    size_t plen = (size_t)(dot - in);
    if (plen >= pack_cap) plen = pack_cap - 1;
    memcpy(pack, in, plen);
    pack[plen] = '\0';
    snprintf(field, field_cap, "%s", dot + 1);
}

static bool parse_query(const char* text, pwq_query_t* q, char* err, size_t err_cap) {
    memset(q, 0, sizeof(*q));
    if (!text || !*text) {
        set_err(err, err_cap, "empty query");
        return false;
    }

    char buf[1024];
    size_t tlen = strlen(text);
    if (tlen >= sizeof(buf)) {
        set_err(err, err_cap, "query too long");
        return false;
    }
    memcpy(buf, text, tlen + 1);
    for (size_t i = 0; i < tlen; i++) if (buf[i] == '\r') buf[i] = '\n';

    char* save = NULL;
    for (char* line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        trim(line);
        if (!*line) continue;
        if (line[0] == 'S' && line[1] == ':') {
            char* p = line + 2;
            trim(p);
            if (strcmp(p, "*") == 0) {
                q->select_all = true;
                continue;
            }
            char* ssave = NULL;
            for (char* tok = strtok_r(p, ",", &ssave); tok; tok = strtok_r(NULL, ",", &ssave)) {
                if (q->select_count >= PWQ_MAX_SELECT) break;
                trim(tok);
                if (!*tok) continue;
                split_dotted(tok, q->select[q->select_count].pack, sizeof(q->select[q->select_count].pack),
                             q->select[q->select_count].field, sizeof(q->select[q->select_count].field));
                snprintf(q->select[q->select_count].label,
                         sizeof(q->select[q->select_count].label), "%s", tok);
                q->select_count++;
            }
        } else if (line[0] == 'F' && line[1] == ':') {
            char* p = line + 2;
            char* fsave = NULL;
            for (char* tok = strtok_r(p, ",", &fsave); tok; tok = strtok_r(NULL, ",", &fsave)) {
                if (q->from_count >= PWQ_MAX_FROM) break;
                trim(tok);
                if (!*tok) continue;
                snprintf(q->from[q->from_count], sizeof(q->from[q->from_count]), "%s", tok);
                q->from_count++;
            }
        } else if (line[0] == 'W' && line[1] == ':') {
            if (q->where_count >= PWQ_MAX_WHERE) continue;
            char* p = line + 2;
            char* p1 = strchr(p, '|');
            if (!p1) continue;
            *p1 = '\0';
            char* p2 = strchr(p1 + 1, '|');
            if (!p2) continue;
            *p2 = '\0';
            trim(p); trim(p1 + 1); trim(p2 + 1);
            split_dotted(p, q->where[q->where_count].pack, sizeof(q->where[q->where_count].pack),
                         q->where[q->where_count].field, sizeof(q->where[q->where_count].field));
            q->where[q->where_count].op = parse_op(p1 + 1);
            snprintf(q->where[q->where_count].value, sizeof(q->where[q->where_count].value), "%s", p2 + 1);
            q->where_count++;
        }
    }

    if (q->from_count == 0) {
        set_err(err, err_cap, "missing FROM");
        return false;
    }
    return true;
}

static const char* skip_ws(const char* p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static const char* skip_json_string(const char* p) {
    if (*p != '"') return p;
    p++;
    while (*p) {
        if (*p == '\\' && p[1]) { p += 2; continue; }
        if (*p == '"') return p + 1;
        p++;
    }
    return p;
}

static const char* skip_json_value(const char* p) {
    p = skip_ws(p);
    if (*p == '"') return skip_json_string(p);
    if (*p == '{' || *p == '[') {
        char open = *p;
        char close = (open == '{') ? '}' : ']';
        int depth = 0;
        while (*p) {
            if (*p == '"') { p = skip_json_string(p); continue; }
            if (*p == open) depth++;
            else if (*p == close) {
                depth--;
                if (depth == 0) return p + 1;
            }
            p++;
        }
        return p;
    }
    while (*p && *p != ',' && *p != '}') p++;
    return p;
}

static bool parse_json_string_value(const char* p, jval_t* out, const char** endp) {
    out->kind = JVAL_STRING;
    size_t n = 0;
    p++; /* skip opening quote */
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) {
            p++;
            if (*p == 'n') out->text[n++] = '\n';
            else if (*p == 'r') out->text[n++] = '\r';
            else if (*p == 't') out->text[n++] = '\t';
            else out->text[n++] = *p;
            p++;
            if (n + 1 >= sizeof(out->text)) break;
            continue;
        }
        if (n + 1 >= sizeof(out->text)) break;
        out->text[n++] = *p++;
    }
    out->text[n] = '\0';
    if (*p == '"') p++;
    if (endp) *endp = p;
    return true;
}

static bool json_get_field(const char* json, const char* field, jval_t* out) {
    const char* p = skip_ws(json);
    if (*p != '{') return false;
    p++;
    while (*p) {
        p = skip_ws(p);
        if (*p == '}') return false;
        if (*p != '"') return false;
        char key[64];
        size_t kn = 0;
        p++;
        while (*p && *p != '"' && kn + 1 < sizeof(key)) {
            if (*p == '\\' && p[1]) p++;
            key[kn++] = *p++;
        }
        key[kn] = '\0';
        if (*p != '"') return false;
        p++;
        p = skip_ws(p);
        if (*p != ':') return false;
        p++;
        p = skip_ws(p);

        bool match = (strcmp(key, field) == 0);
        if (match) {
            memset(out, 0, sizeof(*out));
            if (*p == '"') return parse_json_string_value(p, out, NULL);
            if (strncmp(p, "true", 4) == 0) {
                out->kind = JVAL_BOOL; snprintf(out->text, sizeof(out->text), "true"); return true;
            }
            if (strncmp(p, "false", 5) == 0) {
                out->kind = JVAL_BOOL; snprintf(out->text, sizeof(out->text), "false"); return true;
            }
            if (strncmp(p, "null", 4) == 0) {
                out->kind = JVAL_NULL; snprintf(out->text, sizeof(out->text), "null"); return true;
            }
            out->kind = JVAL_NUMBER;
            size_t n = 0;
            while (p[n] && p[n] != ',' && p[n] != '}' && !isspace((unsigned char)p[n]) &&
                   n + 1 < sizeof(out->text)) {
                out->text[n] = p[n];
                n++;
            }
            out->text[n] = '\0';
            return n > 0;
        }

        p = skip_json_value(p);
        p = skip_ws(p);
        if (*p == ',') p++;
    }
    return false;
}

static bool value_is_number(const jval_t* v) {
    if (v->kind != JVAL_NUMBER) return false;
    if (!v->text[0]) return false;
    char* end = NULL;
    (void)strtod(v->text, &end);
    return end && *end == '\0';
}

static bool in_list(const char* actual, const char* csv) {
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s", csv);
    char* save = NULL;
    for (char* tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        trim(tok);
        if (strcmp(actual, tok) == 0) return true;
    }
    return false;
}

static bool compare_values(const jval_t* actual, pwq_op_t op, const char* expected) {
    if (op == PWQ_OP_IN) return in_list(actual->text, expected);
    if (op == PWQ_OP_NI) return !in_list(actual->text, expected);

    bool num = value_is_number(actual);
    if (num) {
        double a = strtod(actual->text, NULL);
        double e = strtod(expected, NULL);
        switch (op) {
        case PWQ_OP_EQ: return a == e;
        case PWQ_OP_NE: return a != e;
        case PWQ_OP_GT: return a > e;
        case PWQ_OP_LT: return a < e;
        case PWQ_OP_GE: return a >= e;
        case PWQ_OP_LE: return a <= e;
        default: return false;
        }
    }

    int c = strcmp(actual->text, expected);
    switch (op) {
    case PWQ_OP_EQ: return c == 0;
    case PWQ_OP_NE: return c != 0;
    case PWQ_OP_GT: return c > 0;
    case PWQ_OP_LT: return c < 0;
    case PWQ_OP_GE: return c >= 0;
    case PWQ_OP_LE: return c <= 0;
    default: return false;
    }
}

static int from_index(const pwq_query_t* q, const char* pack) {
    if (!pack || !pack[0]) return 0;
    for (uint8_t i = 0; i < q->from_count; i++) {
        if (strcmp(q->from[i], pack) == 0) return (int)i;
    }
    return -1;
}

static bool load_record_json(picowal_db_t* db, uint16_t pack_id, uint32_t record_id,
                             char* out, size_t out_cap) {
    uint32_t key = 0;
    if (!picowal_db_pack_key(pack_id, record_id, &key)) return false;
    int n = picowal_db_get_key(db, key, out, (uint32_t)(out_cap - 1));
    if (n < 0) return false;
    out[n] = '\0';
    return true;
}

static bool csv_has_token(const char* csv, const char* token) {
    if (!csv || !token || !*token) return false;
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", csv);
    char* save = NULL;
    for (char* tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        trim(tok);
        if (strcmp(tok, token) == 0) return true;
    }
    return false;
}

static bool schema_allows_field(picowal_db_t* db, uint16_t pack_id, const char* field) {
    char schema[4097];
    if (!load_record_json(db, PWQ_PACK_SCHEMA, pack_id, schema, sizeof(schema))) return true;
    jval_t fields;
    if (!json_get_field(schema, "fields", &fields) || fields.kind != JVAL_STRING) return true;
    return csv_has_token(fields.text, field);
}

static bool schema_join_field(picowal_db_t* db, uint16_t pack_id, uint16_t target_pack,
                              char* out, size_t out_cap) {
    if (!out || out_cap == 0) return false;
    out[0] = '\0';
    char schema[4097];
    if (!load_record_json(db, PWQ_PACK_SCHEMA, pack_id, schema, sizeof(schema))) return false;
    jval_t joins;
    if (!json_get_field(schema, "joins", &joins) || joins.kind != JVAL_STRING) return false;

    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", joins.text);
    char* save = NULL;
    for (char* tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        trim(tok);
        char* sep = strchr(tok, '=');
        if (!sep) sep = strchr(tok, ':');
        if (!sep) continue;
        *sep = '\0';
        char* k = tok;
        char* v = sep + 1;
        trim(k); trim(v);
        uint16_t id = 0;
        if (!parse_u16_dec(k, PICOWAL_CARD_MAX, &id)) continue;
        if (id != target_pack) continue;
        snprintf(out, out_cap, "%s", v);
        return true;
    }
    return false;
}

static bool resolve_pack_token(picowal_db_t* db, const char* token, uint16_t* out_id) {
    uint16_t pid = 0;
    if (parse_u16_dec(token, PICOWAL_CARD_MAX, &pid)) {
        *out_id = pid;
        return true;
    }

    uint32_t records[PWQ_SCAN_LIMIT];
    uint32_t n = picowal_db_list_records(db, PWQ_PACK_NAMES, records, PWQ_SCAN_LIMIT);
    for (uint32_t i = 0; i < n; i++) {
        char doc[4097];
        if (!load_record_json(db, PWQ_PACK_NAMES, records[i], doc, sizeof(doc))) continue;
        jval_t namev;
        if (!json_get_field(doc, "name", &namev) || namev.kind != JVAL_STRING) continue;
        if (strcasecmp(namev.text, token) != 0) continue;
        jval_t packv;
        if (json_get_field(doc, "pack", &packv) && packv.kind == JVAL_NUMBER) {
            uint16_t mapped = 0;
            if (parse_u16_dec(packv.text, PICOWAL_CARD_MAX, &mapped)) {
                *out_id = mapped;
                return true;
            }
        }
        if (records[i] <= PICOWAL_CARD_MAX) {
            *out_id = (uint16_t)records[i];
            return true;
        }
    }
    return false;
}

static bool find_fk_record(const char* primary_json, const char* joined_pack_token,
                           const char* schema_fk_field, uint32_t* out_record) {
    jval_t v;
    if (schema_fk_field && schema_fk_field[0] &&
        json_get_field(primary_json, schema_fk_field, &v) && v.kind == JVAL_NUMBER) {
        char* end = NULL;
        unsigned long n = strtoul(v.text, &end, 10);
        if (end && *end == '\0' && n <= PICOWAL_RECORD_MAX) {
            *out_record = (uint32_t)n;
            return true;
        }
    }

    char fk1[48];
    char fk2[48];
    snprintf(fk1, sizeof(fk1), "%s_id", joined_pack_token);
    snprintf(fk2, sizeof(fk2), "%s", joined_pack_token);
    if (!json_get_field(primary_json, fk1, &v) && !json_get_field(primary_json, fk2, &v)) return false;
    if (v.kind != JVAL_NUMBER) return false;
    char* end = NULL;
    unsigned long n = strtoul(v.text, &end, 10);
    if (!end || *end != '\0' || n > PICOWAL_RECORD_MAX) return false;
    *out_record = (uint32_t)n;
    return true;
}

bool picowal_query_run(picowal_db_t* db, const char* text,
                       char** out_json, size_t* out_len,
                       char* err, size_t err_cap) {
    if (!db || !text || !out_json || !out_len) {
        set_err(err, err_cap, "invalid arguments");
        return false;
    }
    *out_json = NULL;
    *out_len = 0;

    pwq_query_t q;
    if (!parse_query(text, &q, err, err_cap)) return false;

    for (uint8_t i = 0; i < q.from_count; i++) {
        if (!resolve_pack_token(db, q.from[i], &q.from_ids[i])) {
            set_err(err, err_cap, "FROM pack not found");
            return false;
        }
        if (q.from_ids[i] == PWQ_PACK_USERS) {
            set_err(err, err_cap, "query access to users pack denied");
            return false;
        }
    }

    for (uint8_t wi = 0; wi < q.where_count; wi++) {
        int pidx = from_index(&q, q.where[wi].pack);
        if (pidx < 0) {
            set_err(err, err_cap, "WHERE pack not in FROM");
            return false;
        }
        if (!schema_allows_field(db, q.from_ids[pidx], q.where[wi].field)) {
            set_err(err, err_cap, "WHERE field not in schema");
            return false;
        }
    }
    for (uint8_t si = 0; si < q.select_count; si++) {
        int pidx = from_index(&q, q.select[si].pack);
        if (pidx < 0) {
            set_err(err, err_cap, "SELECT pack not in FROM");
            return false;
        }
        if (!schema_allows_field(db, q.from_ids[pidx], q.select[si].field)) {
            set_err(err, err_cap, "SELECT field not in schema");
            return false;
        }
    }

    uint32_t records[PWQ_SCAN_LIMIT];
    uint32_t rcnt = picowal_db_list_records(db, q.from_ids[0], records, PWQ_SCAN_LIMIT);

    sb_t out = {0};
    if (!sb_append(&out, "{\"rows\":[")) goto oom;

    uint32_t emitted = 0;
    for (uint32_t i = 0; i < rcnt && emitted < PWQ_MAX_RESULTS; i++) {
        char primary[4097];
        if (!load_record_json(db, q.from_ids[0], records[i], primary, sizeof(primary))) continue;

        bool pass = true;
        for (uint8_t wi = 0; wi < q.where_count && pass; wi++) {
            int pidx = from_index(&q, q.where[wi].pack);
            if (pidx < 0) { pass = false; break; }
            char target_json[4097];
            const char* src_json = primary;
            if (pidx > 0) {
                uint32_t ref = 0;
                char fk_field[48] = {0};
                (void)schema_join_field(db, q.from_ids[0], q.from_ids[pidx], fk_field, sizeof(fk_field));
                if (!find_fk_record(primary, q.from[pidx], fk_field, &ref)) { pass = false; break; }
                if (!load_record_json(db, q.from_ids[pidx], ref, target_json, sizeof(target_json))) {
                    pass = false;
                    break;
                }
                src_json = target_json;
            }
            jval_t v;
            if (!json_get_field(src_json, q.where[wi].field, &v)) { pass = false; break; }
            pass = compare_values(&v, q.where[wi].op, q.where[wi].value);
        }
        if (!pass) continue;

        if (emitted++ > 0 && !sb_append_ch(&out, ',')) goto oom;
        if (q.select_all || q.select_count == 0) {
            if (!sb_append(&out, primary)) goto oom;
            continue;
        }

        if (!sb_append_ch(&out, '{')) goto oom;
        bool first = true;
        for (uint8_t si = 0; si < q.select_count; si++) {
            int pidx = from_index(&q, q.select[si].pack);
            if (pidx < 0) continue;
            char target_json[4097];
            const char* src_json = primary;
            if (pidx > 0) {
                uint32_t ref = 0;
                char fk_field[48] = {0};
                (void)schema_join_field(db, q.from_ids[0], q.from_ids[pidx], fk_field, sizeof(fk_field));
                if (!find_fk_record(primary, q.from[pidx], fk_field, &ref)) continue;
                if (!load_record_json(db, q.from_ids[pidx], ref, target_json, sizeof(target_json))) continue;
                src_json = target_json;
            }
            jval_t v;
            if (!json_get_field(src_json, q.select[si].field, &v)) continue;

            if (!first && !sb_append_ch(&out, ',')) goto oom;
            first = false;
            if (!sb_append_json_string(&out, q.select[si].label) || !sb_append_ch(&out, ':')) goto oom;
            if (v.kind == JVAL_NUMBER || v.kind == JVAL_BOOL || v.kind == JVAL_NULL) {
                if (!sb_append(&out, v.text)) goto oom;
            } else {
                if (!sb_append_json_string(&out, v.text)) goto oom;
            }
        }
        if (!sb_append_ch(&out, '}')) goto oom;
    }

    if (!sb_append(&out, "],\"count\":")) goto oom;
    char nbuf[32];
    int nn = snprintf(nbuf, sizeof(nbuf), "%u", emitted);
    if (nn <= 0 || !sb_append_raw(&out, nbuf, (size_t)nn)) goto oom;
    if (!sb_append_ch(&out, '}')) goto oom;

    *out_json = out.data;
    *out_len = out.len;
    return true;

oom:
    free(out.data);
    set_err(err, err_cap, "out of memory");
    return false;
}
