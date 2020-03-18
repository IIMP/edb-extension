#ifndef EDB_CRYPTO_CRYPTO_H_
#define EDB_CRYPTO_CRYPTO_H_

#include <cstdint>
#include <cstdlib>

#include "aes.h"
#include "scope_ptr.h"

namespace edb {
namespace crypto {

template <typename AESCipher, bool padding = true>
int aes_encrypt(const uint8_t *key, size_t key_size, const uint8_t *iv,
                size_t iv_size, const uint8_t *in, size_t in_size,
                uint8_t **out) {
    if (key == nullptr || key_size == 0 || iv == nullptr || iv_size == 0 ||
        in == nullptr || in_size == 0 || out == nullptr)
        return -1;

    int out_size = padding ? static_cast<int>(AESCipher::encrypt_size(in_size))
                           : static_cast<int>(in_size);
    auto keeper =
        edb::make_scope_ptr(reinterpret_cast<uint8_t *>(malloc(out_size)));
    uint8_t *output = keeper.get();
    if (!output)
        return -1;

    AESCipher aes(key, key_size, iv, iv_size, padding);
    out_size = aes.encrypt(in, in_size, output);
    if (out_size > 0) {
        *out = keeper.release();
        return out_size;
    }

    return -1;
}

template <typename AESCipher, bool padding = true>
int aes_decrypt(const uint8_t *key, size_t key_size, const uint8_t *iv,
                size_t iv_size, const uint8_t *in, size_t in_size,
                uint8_t **out) {
    if (key == nullptr || key_size == 0 || iv == nullptr || iv_size == 0 ||
        in == nullptr || in_size == 0 || out == nullptr)
        return -1;

    int out_size = padding ? static_cast<int>(AESCipher::decrypt_size(in_size))
                           : static_cast<int>(in_size);
    auto keeper =
        edb::make_scope_ptr(reinterpret_cast<uint8_t *>(malloc(out_size)));
    uint8_t *output = keeper.get();
    if (!output)
        return -1;

    AESCipher aes(key, key_size, iv, iv_size, padding);
    out_size = aes.decrypt(in, in_size, output);
    if (out_size > 0) {
        *out = keeper.release();
        return out_size;
    }

    return -1;
}

constexpr auto aes_cbc_128_enc = aes_encrypt<AES128CBC>;
constexpr auto aes_cbc_128_dec = aes_decrypt<AES128CBC>;
constexpr auto aes_cbc_128_enc_nopadding = aes_encrypt<AES128CBC, false>;
constexpr auto aes_cbc_128_dec_nopadding = aes_decrypt<AES128CBC, false>;
} // namespace crypto
} // namespace edb
#endif /* ifndef EDB_CRYPTO_CRYPTO_H_ */
