#include "text.h"

extern "C" {
#include <fmgr.h>
}

#include "enclave/bridge/enclave_u.h"
#include "internal.h"

namespace edb {

int text_cmp(Datum a, Datum b) { return compare_value(a, b, ec_text_cmp); }

Datum text_concat(Datum a, Datum b) {
    bytea *lhs = DatumGetByteaPP(a);
    bytea *rhs = DatumGetByteaPP(b);

    size_t lhs_size = VARSIZE_ANY_EXHDR(lhs);
    size_t rhs_size = VARSIZE_ANY_EXHDR(rhs);
    size_t result_size = lhs_size + rhs_size - crypto::kAES128IVSize;
    bytea *result = reinterpret_cast<bytea *>(palloc0(VARHDRSZ + result_size));

    size_t ret;
    sgx_status_t status = ec_text_concat(
        get_edb_enclave_id(), &ret, reinterpret_cast<uint8_t *>(VARDATA(lhs)),
        lhs_size, reinterpret_cast<uint8_t *>(VARDATA(rhs)), rhs_size,
        reinterpret_cast<uint8_t *>(VARDATA(result)), result_size);
    if (status != SGX_SUCCESS || ret == static_cast<size_t>(-1))
        ereport(ERROR, (errmsg("concat text error, status(%08x)", status)));

    SET_VARSIZE(result, VARHDRSZ + ret);

    PG_RETURN_BYTEA_P(result);
}

Datum text_match_like(Datum txt, Datum pat) {
    bytea *text = DatumGetByteaPP(txt);
    bytea *pattern = DatumGetByteaPP(pat);

    size_t text_size = VARSIZE_ANY_EXHDR(text);
    size_t pattern_size = VARSIZE_ANY_EXHDR(pattern);

    int ret;
    sgx_status_t status = ec_text_match_like(
        get_edb_enclave_id(), &ret,
        reinterpret_cast<uint8_t *>(VARDATA(text)), text_size,
        reinterpret_cast<uint8_t *>(VARDATA(pattern)), pattern_size);

    if (status != SGX_SUCCESS || ret < 0)
        ereport(ERROR, (errmsg("match text like error, status(%08x)", status)));

    PG_RETURN_BOOL(ret);
}

} // namespace edb
