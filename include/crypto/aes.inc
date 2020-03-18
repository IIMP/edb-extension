#include <cassert>
#include <cstring>
#include <memory>

#include <openssl/aes.h>
#include <openssl/err.h>

namespace {
using EVP_CIPHER_CTX_ptr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

const EVP_CIPHER *get_cipher(size_t size_in_bits) {
    if (size_in_bits == 128)
        return EVP_aes_128_cbc();
    else if (size_in_bits == 256)
        return EVP_aes_256_cbc();
    else
        assert(false && "Invaid parameter size_in_bits");

    return nullptr;
}
}

namespace edb {
namespace crypto {

template <size_t SizeInBits>
typename AES<SizeInBits>::size_type
AES<SizeInBits>::encrypt_size(size_type input_size) {
    size_type rem_size = input_size % AES_BLOCK_SIZE;

    if (rem_size == 0)
        return input_size + AES_BLOCK_SIZE;
    else
        return input_size + AES_BLOCK_SIZE - rem_size;
}

template <size_t SizeInBits>
typename AES<SizeInBits>::size_type
AES<SizeInBits>::decrypt_size(size_type input_size) {
    return input_size;
}

template <size_t SizeInBits>
AES<SizeInBits>::AES(const byte_type *key, size_type key_size,
                     const byte_type *iv, size_type iv_size, bool padding)
    : padding_(padding), ok_(false) {
    if (key == nullptr || key_size != kKeySize)
        return;

    if (iv == nullptr || iv_size != AES_BLOCK_SIZE)
        return;

    memcpy(key_, key, kKeySize);
    memcpy(iv_, iv, AES_BLOCK_SIZE);
    ok_ = true;
}

template <size_t SizeInBits> AES<SizeInBits>::~AES() {
    memset(key_, 0, kKeySize);
    memset(iv_, 0, AES_BLOCK_SIZE);
}

template <size_t SizeInBits>
int AES<SizeInBits>::encrypt(const byte_type *in, size_type in_size,
                             byte_type *out) {
    if (!ok_ || in == nullptr || in_size == 0 || out == nullptr)
        return -1;

    EVP_CIPHER_CTX_ptr ctx_ptr(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX *ctx = ctx_ptr.get();
    if (!ctx)
        return -1;

    if (EVP_EncryptInit_ex(ctx, get_cipher(SizeInBits), nullptr,
                           reinterpret_cast<const unsigned char *>(key_),
                           reinterpret_cast<const unsigned char *>(iv_)) != 1) {
        return -1;
    }

    if (!padding_)
        assert((in_size % AES_BLOCK_SIZE == 0));

    EVP_CIPHER_CTX_set_padding(ctx, padding_ ? 1 : 0);

    int enc_len;
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(out), &enc_len,
                          reinterpret_cast<const unsigned char *>(in),
                          static_cast<int>(in_size)) != 1)
        return -1;

    int out_size = enc_len;
    if (EVP_EncryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char *>(out + out_size),
                            &enc_len) != 1)
        return -1;

    out_size += enc_len;

    return out_size;
}

template <size_t SizeInBits>
int AES<SizeInBits>::decrypt(const byte_type *in, size_type in_size,
                             byte_type *out) {
    if (!ok_ || in == nullptr ||
        (in_size == 0 || (in_size % AES_BLOCK_SIZE) != 0) || out == nullptr)
        return -1;

    EVP_CIPHER_CTX_ptr ctx_ptr(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX *ctx = ctx_ptr.get();

    if (!ctx)
        return -1;

    if (EVP_DecryptInit_ex(ctx, get_cipher(SizeInBits), nullptr,
                           reinterpret_cast<const unsigned char *>(key_),
                           reinterpret_cast<const unsigned char *>(iv_)) != 1)
        return -1;

    if (!padding_)
        assert((in_size % AES_BLOCK_SIZE == 0));

    EVP_CIPHER_CTX_set_padding(ctx, padding_ ? 1 : 0);

    int out_len;
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(out), &out_len,
                          reinterpret_cast<const unsigned char *>(in),
                          static_cast<int>(in_size)) != 1)
        return -1;

    int out_size = out_len;
    if (EVP_DecryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char *>(out + out_size),
                            &out_len) != 1)
        return -1;

    out_size += out_len;

    return out_size;
}
}
}
