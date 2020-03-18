#include "utils.h"

#include <memory>

#include "crypto/crypto.h"

#ifdef SGX_ENABLE
#include <sgx_trts.h>
#else
#include <cstdio>
#endif

bool read_rand_data(void *buffer, size_t size) {
    sgx_status_t status =
        sgx_read_rand(reinterpret_cast<unsigned char *>(buffer), size);

    return status == SGX_SUCCESS;
}
