#ifndef EDB_VALUE_UTILS_H_
#define EDB_VALUE_UTILS_H_

#include <cstdint>

#include "crypto/crypto.h"

namespace edb {

static constexpr auto kMinDataSize =
    crypto::kAES128IVSize + crypto::kAES128BlockSize;

inline bool is_valid_input_value(uint8_t *input, size_t input_size) {
    return (
        input != nullptr && input_size >= kMinDataSize &&
        ((input_size - crypto::kAES128IVSize) % crypto::kAES128BlockSize == 0));
}

inline bool is_valid_input_int4(uint8_t *input, size_t input_size) {
    return input != nullptr && input_size == kMinDataSize;
}

inline bool is_valid_input_float4(uint8_t *input, size_t input_size) {
    return input != nullptr && input_size == kMinDataSize;
}

int32_t be2h4(uint8_t *input);

void h2be4(int32_t value, uint8_t *output);

int encrypt_value(uint8_t *input, size_t input_size, uint8_t *&output);

int decrypt_value(uint8_t *input, size_t input_size, uint8_t *&output);

} // namespace edb

int printf(const char* fmt, ...);
//int ecall_encrypt_value(uint8_t *input, size_t input_size, char *output);
//int ecall_decrypt_value(uint8_t *input, size_t input_size, char *output);

#endif /* ifndef EDB_VALUE_UTILS_H_ */
