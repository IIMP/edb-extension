#include "enclave_t.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "like_match.h"
#include "edb_cmp.h"
#include "scope_ptr.h"
#include "value_utils.h"

int ec_text_cmp(uint8_t *lhs, size_t lhs_size, uint8_t *rhs, size_t rhs_size) {
    using namespace edb;

    if (!is_valid_input_value(lhs, lhs_size) ||
        !is_valid_input_value(rhs, rhs_size))
        return EDB_CMP_ERR;

    uint8_t *lhs_dec = nullptr;
    int lhs_dec_len = decrypt_value(lhs, lhs_size, lhs_dec);
    if (lhs_dec_len < 1)
        return EDB_CMP_ERR;
    auto lhs_dec_sp = make_scope_ptr(lhs_dec);

    uint8_t *rhs_dec = nullptr;
    int rhs_dec_len = decrypt_value(rhs, rhs_size, rhs_dec);
    if (rhs_dec_len < 1)
        return EDB_CMP_ERR;
    auto rhs_dec_sp = make_scope_ptr(rhs_dec);

    int cmp_sz = std::min(lhs_dec_len, rhs_dec_len);
    int cmp_val = strncmp(reinterpret_cast<char *>(lhs_dec),
                          reinterpret_cast<char *>(rhs_dec), cmp_sz);
    if (cmp_val != 0)
        return cmp_val < 0 ? -1 : 1;

    return (lhs_dec_len == rhs_dec_len) ? 0
                                        : (lhs_dec_len < rhs_dec_len ? -1 : 1);
}

size_t ec_text_concat(uint8_t *lhs, size_t lhs_size, uint8_t *rhs,
                      size_t rhs_size, uint8_t *result, size_t result_size) {
    using namespace edb;

    if (!is_valid_input_value(lhs, lhs_size) ||
        !is_valid_input_value(rhs, rhs_size))
        return -1;

    uint8_t *lhs_dec = nullptr;
    int lhs_dec_len = decrypt_value(lhs, lhs_size, lhs_dec);
    if (lhs_dec_len < 1)
        return -1;
    auto lhs_sp = make_scope_ptr(lhs_dec);

    uint8_t *rhs_dec = nullptr;
    int rhs_dec_len = decrypt_value(rhs, rhs_size, rhs_dec);
    if (rhs_dec_len < 1)
        return -1;
    auto rhs_sp = make_scope_ptr(rhs_dec);

    auto concat_result = make_scope_ptr(
        reinterpret_cast<uint8_t *>(malloc(lhs_dec_len + rhs_dec_len - 1)));
    memcpy(concat_result.get(), lhs_dec, lhs_dec_len - 1);
    memcpy(concat_result.get() + lhs_dec_len - 1, rhs_dec, rhs_dec_len);

    uint8_t *concat_result_enc = nullptr;
    int concat_result_enc_len = encrypt_value(
        concat_result.get(), lhs_dec_len + rhs_dec_len - 1, concat_result_enc);
    if (concat_result_enc_len < 0)
        return -1;
    auto concat_result_enc_sp = make_scope_ptr(concat_result_enc);

    if (result != nullptr &&
        result_size >= static_cast<size_t>(concat_result_enc_len))
        memcpy(result, concat_result_enc, concat_result_enc_len);

    return concat_result_enc_len;
}

int ec_text_match_like(uint8_t *text, size_t text_size, uint8_t *pattern,
                       size_t pattern_size) {
    using namespace edb;

    if (!is_valid_input_value(text, text_size) ||
        !is_valid_input_value(pattern, pattern_size))
        return -1;

    uint8_t *text_dec = nullptr;
    int text_dec_len = decrypt_value(text, text_size, text_dec);
    if (text_dec_len < 1)
        return -1;
    auto text_dec_sp = make_scope_ptr(text_dec);

    uint8_t *pattern_dec = nullptr;
    int pattern_dec_len = decrypt_value(pattern, pattern_size, pattern_dec);
    if (pattern_dec_len < 1)
        return -1;
    auto pattern_dec_sp = make_scope_ptr(pattern_dec);

    int ret =
        match_text(reinterpret_cast<char *>(text_dec), text_dec_len - 1,
                   reinterpret_cast<char *>(pattern_dec), pattern_dec_len - 1);

    return ret == LIKE_TRUE;
}
