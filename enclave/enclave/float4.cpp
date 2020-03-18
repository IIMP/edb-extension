#include "enclave_t.h"

#include <cmath>
#include <cstring>

#include "edb_cmp.h"
#include "scope_ptr.h"
#include "value_utils.h"

static inline bool check_float4_len(size_t len) { return len == sizeof(float); }

#define DEFINE_FLOAT4_FUNC(name, op)                                           \
    int ec_float4_##name(uint8_t *lhs, size_t lhs_size, uint8_t *rhs,          \
                         size_t rhs_size, uint8_t *result,                     \
                         size_t result_size) {                                 \
        using namespace edb;                                                   \
                                                                               \
        if (!is_valid_input_float4(lhs, lhs_size) ||                           \
            !is_valid_input_float4(rhs, rhs_size) || result == nullptr ||      \
            result_size < lhs_size)                                            \
            return -1;                                                         \
                                                                               \
        uint8_t *lhs_dec;                                                      \
        int lhs_dec_len = decrypt_value(lhs, lhs_size, lhs_dec);               \
        if (lhs_dec_len < 0)                                                   \
            return -1;                                                         \
        auto lhs_sp = make_scope_ptr(lhs_dec);                                 \
                                                                               \
        if (!check_float4_len(lhs_dec_len))                                    \
            return -1;                                                         \
                                                                               \
        uint8_t *rhs_dec;                                                      \
        int rhs_dec_len = decrypt_value(rhs, rhs_size, rhs_dec);               \
        if (rhs_dec_len < 0)                                                   \
            return -1;                                                         \
        auto rhs_sp = make_scope_ptr(rhs_dec);                                 \
                                                                               \
        if (!check_float4_len(rhs_dec_len))                                    \
            return -1;                                                         \
                                                                               \
        int32_t a = be2h4(lhs_dec);                                            \
        int32_t b = be2h4(rhs_dec);                                            \
        float val = op(*reinterpret_cast<float *>(&a),                         \
                       *reinterpret_cast<float *>(&b));                        \
                                                                               \
        uint8_t beval[sizeof(int32_t)];                                        \
        h2be4(*reinterpret_cast<int32_t *>(&val), beval);                      \
                                                                               \
        uint8_t *enc;                                                          \
        int enc_len = encrypt_value(beval, sizeof(beval), enc);                \
        if (enc_len < 0)                                                       \
            return -1;                                                         \
        auto enc_sp = make_scope_ptr(enc);                                     \
                                                                               \
        memcpy(result, enc, enc_len);                                          \
                                                                               \
        return enc_len;                                                        \
    }

#define DO_FLOAT4_OP(a, b, op) ((a)op(b))

#define FLOAT4_ADD(a, b) DO_FLOAT4_OP(a, b, +)
#define FLOAT4_SUB(a, b) DO_FLOAT4_OP(a, b, -)
#define FLOAT4_MUL(a, b) DO_FLOAT4_OP(a, b, *)
#define FLOAT4_DIV(a, b) DO_FLOAT4_OP(a, b, /)
#define FLOAT4_MOD(a, b) fmodf((a), (b))
#define FLOAT4_POW(a, b) powf((a), (b))

DEFINE_FLOAT4_FUNC(add, FLOAT4_ADD)
DEFINE_FLOAT4_FUNC(sub, FLOAT4_SUB)
DEFINE_FLOAT4_FUNC(mul, FLOAT4_MUL)
DEFINE_FLOAT4_FUNC(div, FLOAT4_DIV)
DEFINE_FLOAT4_FUNC(mod, FLOAT4_MOD)
DEFINE_FLOAT4_FUNC(pow, FLOAT4_POW)

int ec_float4_cmp(uint8_t *lhs, size_t lhs_size, uint8_t *rhs,
                  size_t rhs_size) {
    using namespace edb;

    if (!is_valid_input_float4(lhs, lhs_size) ||
        !is_valid_input_float4(rhs, rhs_size))
        return EDB_CMP_ERR;

    uint8_t *lhs_dec;
    int lhs_dec_len = decrypt_value(lhs, lhs_size, lhs_dec);
    if (lhs_dec_len < 0)
        return EDB_CMP_ERR;
    auto lhs_sp = make_scope_ptr(lhs_dec);

    if (!check_float4_len(lhs_dec_len))
        return EDB_CMP_ERR;

    uint8_t *rhs_dec;
    int rhs_dec_len = decrypt_value(rhs, rhs_size, rhs_dec);
    if (rhs_dec_len < 0)
        return EDB_CMP_ERR;
    auto rhs_sp = make_scope_ptr(rhs_dec);

    if (!check_float4_len(rhs_dec_len))
        return EDB_CMP_ERR;

    int32_t a = be2h4(lhs_dec);
    int32_t b = be2h4(rhs_dec);
    float ret = *reinterpret_cast<float *>(&a) - *reinterpret_cast<float *>(&b);

    return ret < 0 ? -1 : (ret > 0 ? 1 : 0);
}

int ec_float4_div2(uint8_t *lhs, size_t lhs_size, float rhs, uint8_t *result,
                   size_t result_size) {
    using namespace edb;

    if (!is_valid_input_float4(lhs, lhs_size) || result == nullptr ||
        result_size < lhs_size)
        return -1;

    uint8_t *lhs_dec;
    int lhs_dec_len = decrypt_value(lhs, lhs_size, lhs_dec);
    if (lhs_dec_len < 0)
        return -1;
    auto lhs_sp = make_scope_ptr(lhs_dec);

    if (!check_float4_len(lhs_dec_len))
        return -1;

    int32_t a = be2h4(lhs_dec);
    float val = *reinterpret_cast<float *>(&a) / rhs;
    uint8_t beval[sizeof(int32_t)];
    h2be4(*reinterpret_cast<int32_t *>(&val), beval);

    uint8_t *enc;
    int enc_len = encrypt_value(beval, sizeof(beval), enc);
    if (enc_len < 0)
        return -1;
    auto enc_sp = make_scope_ptr(enc);

    memcpy(result, enc, enc_len);

    return enc_len;
}
