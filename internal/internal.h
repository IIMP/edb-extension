#ifndef EDB_INTERNAL_INTERNAL_H_
#define EDB_INTERNAL_INTERNAL_H_

extern "C" {
#include <postgres.h>

#include <common/base64.h>
#include <fmgr.h>
#include <utils/builtins.h>
}

#include <cstdbool>
#include <sgx_urts.h>

#include "crypto/aes.h"
#include "edb_cmp.h"

namespace edb {

constexpr size_t kMinDataSize =
    crypto::kAES128IVSize + crypto::kAES128BlockSize;

sgx_enclave_id_t get_edb_enclave_id();

Datum edb_value_in(Datum value);

Datum edb_value_out(Datum value);

using sgx_value_comparator = sgx_status_t (*)(sgx_enclave_id_t eid, int *ret,
                                              uint8_t *lhs, size_t lhs_size,
                                              uint8_t *rhs, size_t rhs_size);
int compare_value(Datum a, Datum b, sgx_value_comparator comparator);

using sgx_math_op = sgx_status_t (*)(sgx_enclave_id_t eid, int *ret,
                                     uint8_t *lhs, size_t lhs_size,
                                     uint8_t *rhs, size_t rhs_size,
                                     uint8_t *result, size_t result_size);

Datum do_math_op(Datum a, Datum b, sgx_math_op math_op);

template <typename Function, typename T>
Datum do_math_op(Datum a, T b, Function func) {
    bytea *lhs = DatumGetByteaPP(a);

    size_t lhs_size = VARSIZE_ANY_EXHDR(lhs);
    if (lhs_size < kMinDataSize)
        ereport(ERROR, (errmsg("corrupted data")));

    uint8_t *lhs_data = reinterpret_cast<uint8_t *>(VARDATA(lhs));
    bytea *result = reinterpret_cast<bytea *>(palloc(VARHDRSZ + lhs_size));

    int ret;
    sgx_enclave_id_t eid = get_edb_enclave_id();
    sgx_status_t status =
        func(eid, &ret, lhs_data, lhs_size, b,
             reinterpret_cast<uint8_t *>(VARDATA(result)), lhs_size);
    if (status != SGX_SUCCESS || ret < 0)
        ereport(ERROR, (errmsg("do math op error, status(%08x) ret(%d).",
                               status, ret)));
    SET_VARSIZE(result, VARHDRSZ + ret);

    PG_RETURN_BYTEA_P(result);
}

} // namespace edb

#endif /* ifndef EDB_INTERNAL_INTERNAL_H_ */
