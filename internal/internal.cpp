#include "internal.h"
#include "enclave/bridge/enclave_u.h"
#include <sgx_uswitchless.h>

namespace {
typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

static sgx_enclave_id_t s_edi = 0;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                ereport(ERROR, (errmsg("Info: %s\n", sgx_errlist[idx].sug)));
            ereport(ERROR, (errmsg("Error: %s\n", sgx_errlist[idx].msg)));
            break;
        }
    }

    if (idx == ttl)
        ereport(ERROR, (errmsg("Error: Unexpected error occurred.\n")));
}

int initialize_enclave(void) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_launch_token_t token = {0};
    int updated = 0;
#if 1
    sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
    us_config.num_uworkers = 1;
    us_config.num_tworkers = 1;

    const void* enclave_ex_p[32] = { 0 };
    enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = (const void*)&us_config;
#endif
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    //ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
    //                         &s_edi, NULL);
    ret = sgx_create_enclave_ex(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                            &s_edi, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, enclave_ex_p);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        ereport(ERROR, (errmsg("enclave init switchless error: %08x\n", ret)));
        return -1;
    }
    //ereport(ERROR, (errmsg("switchless!\n")));

    return 0;
}

} // namespace

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    ereport(INFO, (errmsg("%s", str)));
}

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
#ifdef DEBUG_MODE
Datum edb_value_in(const char *value_in, size_t value_size) {
    int rem_size = value_size % AES_BLOCK_SIZE;
    int data_size;
    bytea *value_out;

    if(rem_size == 0) {
        data_size = value_size + AES_BLOCK_SIZE;
    } else {
        data_size = value_size + AES_BLOCK_SIZE - rem_size;
    }
    //ereport(INFO, (errmsg("encrypte value: ENC(%d)  Len:%d", *((int *)value_in), data_size)));

    value_out = reinterpret_cast<bytea *>(palloc0(VARHDRSZ + data_size));
    sgx_status_t status = ecall_encrypt_value(s_edi, &data_size, (uint8_t *)value_in, value_size, VARDATA(value_out));
    if(status != SGX_SUCCESS || data_size <= 0) {
        ereport(ERROR, (errmsg("encrypte value error, status(%08x) ret(%d).",
                               status, data_size)));
    }
    SET_VARSIZE(value_out, VARHDRSZ + data_size);

    PG_RETURN_BYTEA_P(value_out);
}

Datum edb_value_out(const char *value_in, size_t value_size) {
    int data_size;
    char *value_out = reinterpret_cast<char *>(palloc0(value_size * sizeof(char)));

    sgx_status_t status = ecall_decrypt_value(s_edi, &data_size, (uint8_t *)value_in, value_size, value_out);
    if(status != SGX_SUCCESS || data_size <= 0) {
        ereport(ERROR, (errmsg("decrypt value error, status(%08x) ret(%d).",
                               status, data_size)));
    }
    ereport(INFO, (errmsg("decrypte value: DEC(%d)  Len:%d", *((int *)value_out), data_size)));
    PG_RETURN_CSTRING(value_out);
}
#else
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
#endif

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
    if (status != SGX_SUCCESS) {
        print_error_message(status);
    } else if ( ret == EDB_CMP_ERR) {
        ereport(ERROR, (errmsg("compare data error, status(%08x).", status)));
    }
        

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
