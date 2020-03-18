#ifndef EDB_CRYPTO_AES_H_
#define EDB_CRYPTO_AES_H_

#include <cstdint>

#include <openssl/aes.h>
#include <openssl/evp.h>

namespace edb {
namespace crypto {

template <size_t SizeInBits> class AES {
  public:
    enum { kKeySize = SizeInBits / 8 };
    static_assert((SizeInBits == 128 || SizeInBits == 256),
                  "Only support SizeInBits be 128 or 256");

    using byte_type = uint8_t;
    using size_type = size_t;

    static constexpr size_type kBlockSize = AES_BLOCK_SIZE;

    AES(const byte_type *key, size_type key_size, const byte_type *iv,
        size_type iv_size, bool padding = false);
    ~AES();

    int encrypt(const byte_type *in, size_type in_size, byte_type *out);
    int decrypt(const byte_type *in, size_type in_size, byte_type *out);

    static size_type encrypt_size(size_type input_size);
    static size_type decrypt_size(size_type input_size);

  private:
    byte_type key_[kKeySize];
    byte_type iv_[AES_BLOCK_SIZE];
    bool padding_;
    bool ok_;
};

using AES128CBC = AES<128>;

constexpr size_t kAES128KeySize = 16;
constexpr size_t kAES128IVSize = 16;
constexpr size_t kAES128BlockSize = AES128CBC::kBlockSize;

} // namespace crypto
} // namespace edb

#include "aes.inc"

#endif /* EDB_CRYPTO_AES_H_ */
