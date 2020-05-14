#include "enclave_t.h"

#include <cmath>
#include <cstring>

#include "edb_cmp.h"
#include "scope_ptr.h"
#include "value_utils.h"

static inline bool check_int4_len(size_t len) { return len == sizeof(int32_t); }

#if 0
        int32_t a = be2h4(lhs_dec);                                            
        int32_t b = be2h4(rhs_dec);                                            \
        int32_t val = op(a, b);                                                \
                                                                               \
        uint8_t beval[sizeof(int32_t)];                                        \
        h2be4(val, beval);                                                     \
                                                                               \
        uint8_t *enc;                                                          \
        int enc_len = encrypt_value(beval, sizeof(beval), enc);                
#endif

#define DEFINE_INT4_FUNC(name, op)                                             \
    int ec_int4_##name(uint8_t *lhs, size_t lhs_size, uint8_t *rhs,            \
                       size_t rhs_size, uint8_t *result, size_t result_size) { \
        using namespace edb;                                                   \
                                                                               \
        if (!is_valid_input_int4(lhs, lhs_size) ||                             \
            !is_valid_input_int4(rhs, rhs_size) || result == nullptr ||        \
            result_size < lhs_size)                                            \
            return -1;                                                         \
                                                                               \
        uint8_t *lhs_dec;                                                      \
        int lhs_dec_len = decrypt_value(lhs, lhs_size, lhs_dec);               \
        if (lhs_dec_len < 0)                                                   \
            return -1;                                                         \
        auto lhs_sp = make_scope_ptr(lhs_dec);                                 \
                                                                               \
        if (!check_int4_len(lhs_dec_len))                                      \
            return -1;                                                         \
                                                                               \
        uint8_t *rhs_dec;                                                      \
        int rhs_dec_len = decrypt_value(rhs, rhs_size, rhs_dec);               \
        if (rhs_dec_len < 0)                                                   \
            return -1;                                                         \
        auto rhs_sp = make_scope_ptr(rhs_dec);                                 \
                                                                               \
        if (!check_int4_len(rhs_dec_len))                                      \
            return -1;                                                         \
                                                                               \
        int32_t val = op(*(int32_t *)lhs_dec, *(int32_t *)rhs_dec);            \
        uint8_t *enc;                                                          \
        int enc_len = encrypt_value((uint8_t *)&val, sizeof(int32_t), enc);    \
        if (enc_len < 0)                                                       \
            return -1;                                                         \
        auto enc_sp = make_scope_ptr(enc);                                     \
                                                                               \
        memcpy(result, enc, enc_len);                                          \
                                                                               \
        return enc_len;                                                        \
    }

#define DO_INT4_OP(a, b, op) ((a)op(b))

#define INT4_ADD(a, b) DO_INT4_OP(a, b, +)
#define INT4_SUB(a, b) DO_INT4_OP(a, b, -)
#define INT4_MUL(a, b) DO_INT4_OP(a, b, *)
#define INT4_DIV(a, b) DO_INT4_OP(a, b, /)
#define INT4_MOD(a, b) DO_INT4_OP(a, b, %)
#define INT4_POW(a, b) (int32_t) pow((a), (b))

DEFINE_INT4_FUNC(add, INT4_ADD)
DEFINE_INT4_FUNC(sub, INT4_SUB)
DEFINE_INT4_FUNC(mul, INT4_MUL)
DEFINE_INT4_FUNC(div, INT4_DIV)
DEFINE_INT4_FUNC(mod, INT4_MOD)
DEFINE_INT4_FUNC(pow, INT4_POW)

int ec_int4_cmp(uint8_t *lhs, size_t lhs_size, uint8_t *rhs, size_t rhs_size) {
    using namespace edb;

    if (!is_valid_input_int4(lhs, lhs_size) ||
        !is_valid_input_int4(rhs, rhs_size))
        return EDB_CMP_ERR;

    uint8_t *lhs_dec;
    int lhs_dec_len = decrypt_value(lhs, lhs_size, lhs_dec);
    if (lhs_dec_len < 0)
        return EDB_CMP_ERR;
    auto lhs_sp = make_scope_ptr(lhs_dec);

    if (!check_int4_len(lhs_dec_len))
        return EDB_CMP_ERR;

    uint8_t *rhs_dec;
    int rhs_dec_len = decrypt_value(rhs, rhs_size, rhs_dec);
    if (rhs_dec_len < 0)
        return EDB_CMP_ERR;
    auto rhs_sp = make_scope_ptr(rhs_dec);

    if (!check_int4_len(rhs_dec_len))
        return EDB_CMP_ERR;
#if 0
    int32_t a = be2h4(lhs_dec);
    int32_t b = be2h4(rhs_dec);
    int32_t ret = a - b;
#endif
    int32_t ret = *(int32_t *)lhs_dec - *(int32_t *)rhs_dec;
    
    return (ret == 0) ? 0 : (ret < 0 ? -1 : 1);
}

int ec_int4_div2(uint8_t *lhs, size_t lhs_size, int rhs, uint8_t *result,
                 size_t result_size) {
    using namespace edb;

    if (!is_valid_input_int4(lhs, lhs_size) || result == nullptr ||
        result_size < lhs_size)
        return -1;

    uint8_t *lhs_dec;
    int lhs_dec_len = decrypt_value(lhs, lhs_size, lhs_dec);
    if (lhs_dec_len < 0)
        return -1;
    auto lhs_sp = make_scope_ptr(lhs_dec);

    if (!check_int4_len(lhs_dec_len))
        return -1;

    int32_t val = be2h4(lhs_dec) / rhs;

    uint8_t beval[sizeof(int32_t)];
    h2be4(val, beval);

    uint8_t *enc;
    int enc_len = encrypt_value(beval, sizeof(beval), enc);
    if (enc_len < 0)
        return -1;
    auto enc_sp = make_scope_ptr(enc);

    memcpy(result, enc, enc_len);

    return enc_len;
}
