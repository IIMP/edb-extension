#include "value_utils.h"

#include <cstring>

#include "byte_view.h"
#include "crypto/crypto.h"
#include "scope_ptr.h"
#include "utils.h"

namespace edb {

int32_t be2h4(uint8_t *input) {
    return byte_view(input, sizeof(int32_t)).read<int32_t>(0);
}

void h2be4(int32_t value, uint8_t *output) {
    byte_view bv(output, sizeof(int32_t));
    bv.write<int32_t>(0, value);
}

int encrypt_value(uint8_t *input, size_t input_size, uint8_t *&output) {
    using namespace crypto;

    uint8_t iv[kAES128IVSize];
    if (!read_rand_data(iv, sizeof(iv)))
        return -1;

    const char *key = ENCRYPT_KEY;

    uint8_t *enc;
    int enc_len =
        aes_cbc_128_enc(reinterpret_cast<const uint8_t *>(key), kAES128KeySize,
                        iv, sizeof(iv), input, input_size, &enc);
    if (enc_len < 0)
        return -1;

    auto enc_sp = make_scope_ptr(enc);

    auto res = make_scope_ptr(
        reinterpret_cast<uint8_t *>(malloc(kAES128IVSize + enc_len)));
    if (res == nullptr)
        return -1;

    memcpy(res.get(), iv, sizeof(iv));
    memcpy(res.get() + sizeof(iv), enc, enc_len);

    output = res.release();

    return static_cast<int>(kAES128IVSize) + enc_len;
}

int decrypt_value(uint8_t *input, size_t input_size, uint8_t *&output) {
    using namespace crypto;

    if (!is_valid_input_value(input, input_size))
        return -1;

    const char *key = ENCRYPT_KEY;
    int dec_len =
        aes_cbc_128_dec(reinterpret_cast<const uint8_t *>(key), kAES128KeySize,
                        input, kAES128IVSize, input + kAES128IVSize,
                        input_size - kAES128IVSize, &output);

    return dec_len;
}
} // namespace edb
