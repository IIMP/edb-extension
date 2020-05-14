#include "enclave_t.h"
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

int ecall_encrypt_value(uint8_t *input, size_t input_size, char *output) {
    uint8_t *out;
    int len;
#if 0
    char debug_buffer[128];
    int debug_len;
#endif
    len = edb::encrypt_value(input, input_size, out);
    if(len <= 0) {
         return len;
    }
#if 0
    debug_len = snprintf(debug_buffer, 128, "output size: %d output:", len);
    for(int i=0; i<len; i++) {
        debug_len += snprintf(debug_buffer + debug_len, 128-debug_len, "%02x", out[i]);
    }
    printf("%s", debug_buffer);
#endif
    memcpy(output, out, len);
    return len;
}

int ecall_decrypt_value(uint8_t *input, size_t input_size, char *output) {
    uint8_t *out;
    int len;
#if 0
    char debug_buffer[128];
    int debug_len;
#endif
    

#if 0
    debug_len = snprintf(debug_buffer, 128, "input size: %d input:", input_size);
    for(int i=0; i<input_size; i++) {
        debug_len += snprintf(debug_buffer + debug_len, 128-debug_len, "%02x", input[i]);
    }
    printf("%s", debug_buffer);
#endif
    len = edb::decrypt_value(input, input_size, out);
    //printf("Decrypted result: %d, len: %d", *((int *)out), len);
    if(len <= 0)
        return len;
    memcpy(output, out, len);
    return len;
}

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}