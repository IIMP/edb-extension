#include "internal.h"

namespace {

static sgx_enclave_id_t s_edi = 0;

int initialize_enclave(void) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_launch_token_t token = {0};
    int updated = 0;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                             &s_edi, NULL);
    if (ret != SGX_SUCCESS) {
        ereport(ERROR, (errmsg("enclave init error: %08x\n", ret)));
        return -1;
    }

    return 0;
}

} // namespace

extern "C" {

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

void _PG_init(void) {
    if (s_edi == 0) {
        if (initialize_enclave() < 0) {
            ereport(ERROR, (errmsg("init enclave failed")));
        }
    }
}

void _PG_fini(void) {
    if (s_edi != 0) {
        sgx_destroy_enclave(s_edi);
        s_edi = 0;
    }
}
}

namespace edb {

sgx_enclave_id_t get_edb_enclave_id() { return s_edi; }

Datum edb_value_in(Datum value) {
    const char *str = DatumGetCString(value);
    size_t str_len = strlen(str);
    unsigned data_size = pg_b64_dec_len(static_cast<int>(str_len));
    bytea *data = reinterpret_cast<bytea *>(palloc0(VARHDRSZ + data_size));
    data_size = pg_b64_decode(str, static_cast<int>(str_len), VARDATA(data));
    SET_VARSIZE(data, VARHDRSZ + data_size);

    PG_RETURN_BYTEA_P(data);
}

Datum edb_value_out(Datum value) {
    bytea *data = DatumGetByteaPP(value);
    size_t data_size = VARSIZE_ANY_EXHDR(data);
    size_t str_len = pg_b64_enc_len(static_cast<int>(data_size));
    char *str = reinterpret_cast<char *>(palloc0((str_len + 1) * sizeof(char)));
    pg_b64_encode(VARDATA(data), static_cast<int>(data_size), str);

    PG_RETURN_CSTRING(str);
}

int compare_value(Datum a, Datum b, sgx_value_comparator comparator) {
    bytea *lhs = DatumGetByteaPP(a);
    bytea *rhs = DatumGetByteaPP(b);

    size_t lhs_size = VARSIZE_ANY_EXHDR(lhs);
    size_t rhs_size = VARSIZE_ANY_EXHDR(rhs);

    if (lhs_size < kMinDataSize || rhs_size < kMinDataSize)
        ereport(ERROR, (errmsg("corrupted data")));

    uint8_t *lhs_data = reinterpret_cast<uint8_t *>(VARDATA(lhs));
    uint8_t *rhs_data = reinterpret_cast<uint8_t *>(VARDATA(rhs));

    int ret;
    sgx_enclave_id_t eid = get_edb_enclave_id();
    sgx_status_t status =
        comparator(eid, &ret, lhs_data, lhs_size, rhs_data, rhs_size);
    if (status != SGX_SUCCESS || ret == EDB_CMP_ERR)
        ereport(ERROR, (errmsg("compare data error, status(%08x).", status)));

    return ret;
}

Datum do_math_op(Datum a, Datum b, sgx_math_op math_op) {
    bytea *lhs = DatumGetByteaPP(a);
    bytea *rhs = DatumGetByteaPP(b);

    size_t lhs_size = VARSIZE_ANY_EXHDR(lhs);
    size_t rhs_size = VARSIZE_ANY_EXHDR(rhs);

    if (lhs_size < kMinDataSize || rhs_size < kMinDataSize ||
        lhs_size != rhs_size)
        ereport(ERROR, (errmsg("corrupted data")));

    uint8_t *lhs_data = reinterpret_cast<uint8_t *>(VARDATA(lhs));
    uint8_t *rhs_data = reinterpret_cast<uint8_t *>(VARDATA(rhs));
    bytea *result = reinterpret_cast<bytea *>(palloc(VARHDRSZ + lhs_size));

    int ret;
    sgx_enclave_id_t eid = get_edb_enclave_id();
    sgx_status_t status =
        math_op(eid, &ret, lhs_data, lhs_size, rhs_data, rhs_size,
                reinterpret_cast<uint8_t *>(VARDATA(result)), lhs_size);
    if (status != SGX_SUCCESS || ret < 0)
        ereport(ERROR, (errmsg("do math op error, status(%08x) ret(%d).", status, ret)));

    SET_VARSIZE(result, VARHDRSZ + ret);

    PG_RETURN_BYTEA_P(result);
}

} // namespace edb
