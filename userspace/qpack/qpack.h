/*
 * QPACK static-only decoder (RFC 9204).
 *
 * Scope of this phase (6d1):
 *   - Static table (99 entries, RFC 9204 Appendix A).
 *   - Field-section prefix: Required Insert Count + Sign+DeltaBase.
 *     Static-only ⇒ both MUST be 0; we reject otherwise (Required
 *     Insert Count > 0 implies dynamic-table dependency).
 *   - Field line representations:
 *       * Indexed Field Line (T=1, S=1)         — static-table index
 *       * Literal Field Line With Name Reference (T=01, S=1)
 *       * Literal Field Line With Literal Name  (T=001)
 *   - Both name and value strings stored as raw 7+/3+ prefix-encoded
 *     varints with H bit. H=1 (Huffman) is rejected in this phase
 *     (dispatched in 6d2).
 *
 * No allocation. Caller supplies an output array of decoded fields
 * pointing into either the input buffer (for literal pass-through)
 * or the static-table strings (for indexed names/values).
 *
 * QPACK literal Indexed-with-Post-Base / Literal-with-Post-Base name
 * representations are dynamic-only and rejected.
 */
#ifndef PICOWEB_USERSPACE_QPACK_QPACK_H
#define PICOWEB_USERSPACE_QPACK_QPACK_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    const uint8_t* name;
    size_t         name_len;
    const uint8_t* value;
    size_t         value_len;
} qpack_field_t;

typedef enum {
    QPACK_OK                  = 0,
    QPACK_ERR_TRUNCATED       = -1,  /* input shorter than declared */
    QPACK_ERR_BAD_VARINT      = -2,
    QPACK_ERR_INDEX_OOR       = -3,  /* static index out of range */
    QPACK_ERR_DYNAMIC_REQ     = -4,  /* peer encoding needs dyn-table */
    QPACK_ERR_HUFFMAN         = -5,  /* H bit set; not yet supported */
    QPACK_ERR_OUTPUT_OVERFLOW = -6,
    QPACK_ERR_RESERVED_REPR   = -7   /* unrecognized representation bits */
} qpack_status_t;

/* Look up a static-table entry. Returns 0 on success, -1 on out-of-range.
 * Output strings are NUL-terminated literals from the table. value may
 * be empty (some static entries have no value). */
int qpack_static_get(uint64_t index,
                     const char** out_name, size_t* out_name_len,
                     const char** out_value, size_t* out_value_len);

/* Decode a complete encoded field section.
 *
 *   in / in_len     : the full QPACK field section bytes (prefix + body).
 *   out             : caller array sized `out_cap`.
 *   out_count_in_out: in: capacity, out: decoded field count.
 *
 * Returns 0 on success, negative error code otherwise. Output field
 * pointers either point into `in` (for literal-name and literal-value)
 * or into static-table string literals (which have static lifetime).
 */
qpack_status_t qpack_decode_field_section(const uint8_t* in, size_t in_len,
                                          qpack_field_t* out,
                                          size_t* out_count_in_out);

/* Encode a single Indexed Field Line (T=1, S=1) into out. Returns
 * bytes written, 0 on overflow or out-of-range index. */
size_t qpack_encode_indexed_static(uint8_t* out, size_t cap, uint64_t index);

/* Encode a Literal Field Line With Name Reference (T=01, S=1, N=0,
 * H=0). Returns bytes written, 0 on overflow / OOR / value too big. */
size_t qpack_encode_literal_static_name(uint8_t* out, size_t cap,
                                        uint64_t name_index,
                                        const uint8_t* value, size_t value_len);

/* Encode a Literal Field Line With Literal Name (T=001, N=0, H=0).
 * Returns bytes written, 0 on overflow. */
size_t qpack_encode_literal(uint8_t* out, size_t cap,
                            const uint8_t* name, size_t name_len,
                            const uint8_t* value, size_t value_len);

/* Encode the empty (static-only) field-section prefix: two zero
 * varints. Always 2 bytes; returns 2 or 0 on overflow. */
size_t qpack_encode_prefix_empty(uint8_t* out, size_t cap);

/* Static table size (RFC 9204 Appendix A). */
#define QPACK_STATIC_TABLE_SIZE 99u

#endif
