extern "C" {
#include <postgres.h>

#include <fmgr.h>
#include <utils/array.h>
}

#include "internal/int4.h"
#include "internal/internal.h"

extern "C" {

#ifdef DEBUG_MODE

PG_FUNCTION_INFO_V1(edb_int4_in);
Datum edb_int4_in(PG_FUNCTION_ARGS) {
    const char *str = PG_GETARG_CSTRING(0);
    int32 num = pg_strtoint32(str);
    

    //return edb::edb_value_in((const char *)&num, sizeof(int32));
    char debug_buffer[128];
    int debug_len = 0;
    bytea *data = (bytea *)edb::edb_value_in((const char *)&num, sizeof(int32));
    for(int i=0; i<VARSIZE(data); i++) {
        debug_len += snprintf(debug_buffer + debug_len, 128-debug_len, "%02x", ((uint8_t *)data)[i]);
    }
    ereport(INFO, (errmsg("%s", debug_buffer)));
    return (Datum)data;
}

PG_FUNCTION_INFO_V1(edb_int4_out);
Datum edb_int4_out(PG_FUNCTION_ARGS) {
    bytea *data = PG_GETARG_BYTEA_PP(0);
    size_t data_size = VARSIZE_ANY_EXHDR(data);
    char *str = reinterpret_cast<char *>(palloc(12));

    char debug_buffer[128];
    int debug_len = 0;
    for(int i=0; i<VARSIZE(data); i++) {
        debug_len += snprintf(debug_buffer + debug_len, 128-debug_len, "%02x", ((uint8_t *)data)[i]);
    }
    ereport(INFO, (errmsg("%s", debug_buffer)));

    Datum data_out = edb::edb_value_out(VARDATA(data), data_size);
    //sprintf(str, "%d", *((int *)data_out));
    pg_ltoa(*((int32 *)data_out), str);
    pfree((char *)data_out);
    ereport(INFO, (errmsg("decrypte value: DEC(%s)", str)));
    PG_RETURN_CSTRING(str);
}

#else

PG_FUNCTION_INFO_V1(edb_int4_in);
Datum edb_int4_in(PG_FUNCTION_ARGS) {
    return edb::edb_value_in(PG_GETARG_DATUM(0));
}

PG_FUNCTION_INFO_V1(edb_int4_out);
Datum edb_int4_out(PG_FUNCTION_ARGS) {
    return edb::edb_value_out(PG_GETARG_DATUM(0));
}

#endif

PG_FUNCTION_INFO_V1(edb_int4_cmp);
Datum edb_int4_cmp(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::int4_cmp(a, b);

    PG_RETURN_INT32(ret);
}

PG_FUNCTION_INFO_V1(edb_int4_lt);
Datum edb_int4_lt(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::int4_cmp(a, b);

    PG_RETURN_BOOL(ret < 0);
}

PG_FUNCTION_INFO_V1(edb_int4_le);
Datum edb_int4_le(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::int4_cmp(a, b);

    PG_RETURN_BOOL(ret <= 0);
}

PG_FUNCTION_INFO_V1(edb_int4_gt);
Datum edb_int4_gt(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::int4_cmp(a, b);

    PG_RETURN_BOOL(ret > 0);
}

PG_FUNCTION_INFO_V1(edb_int4_ge);
Datum edb_int4_ge(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::int4_cmp(a, b);

    PG_RETURN_BOOL(ret >= 0);
}

PG_FUNCTION_INFO_V1(edb_int4_eq);
Datum edb_int4_eq(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::int4_cmp(a, b);

    PG_RETURN_BOOL(ret == 0);
}

PG_FUNCTION_INFO_V1(edb_int4_ne);
Datum edb_int4_ne(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::int4_cmp(a, b);

    PG_RETURN_BOOL(ret != 0);
}

PG_FUNCTION_INFO_V1(edb_int4_add);
Datum edb_int4_add(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::int4_add(a, b);
}

PG_FUNCTION_INFO_V1(edb_int4_sub);
Datum edb_int4_sub(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::int4_sub(a, b);
}

PG_FUNCTION_INFO_V1(edb_int4_mul);
Datum edb_int4_mul(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::int4_mul(a, b);
}

PG_FUNCTION_INFO_V1(edb_int4_div);
Datum edb_int4_div(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::int4_div(a, b);
}

PG_FUNCTION_INFO_V1(edb_int4_mod);
Datum edb_int4_mod(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::int4_mod(a, b);
}

PG_FUNCTION_INFO_V1(edb_int4_pow);
Datum edb_int4_pow(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::int4_pow(a, b);
}

PG_FUNCTION_INFO_V1(edb_int4_sum_final);
Datum edb_int4_sum_final(PG_FUNCTION_ARGS) {
    ArrayType *array = PG_GETARG_ARRAYTYPE_P(0);
    ArrayMetaState *extra =
        reinterpret_cast<ArrayMetaState *>(fcinfo->flinfo->fn_extra);
    ArrayIterator array_iterator = array_create_iterator(array, 0, extra);

    bool isnull;
    Datum result;

    array_iterate(array_iterator, &result, &isnull);
    result = PointerGetDatum(DatumGetByteaPCopy(result));

    Datum value;
    while (array_iterate(array_iterator, &value, &isnull)) {
        Datum old = result;
        result = edb::int4_add(old, value);
        pfree(DatumGetPointer(old));
    }

    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(edb_int4_avg_final);
Datum edb_int4_avg_final(PG_FUNCTION_ARGS) {
    ArrayType *array = PG_GETARG_ARRAYTYPE_P(0);
    ArrayMetaState *extra =
        reinterpret_cast<ArrayMetaState *>(fcinfo->flinfo->fn_extra);
    ArrayIterator array_iterator = array_create_iterator(array, 0, extra);

    bool isnull;
    Datum result;

    array_iterate(array_iterator, &result, &isnull);
    result = PointerGetDatum(DatumGetByteaPCopy(result));

    Datum value;
    while (array_iterate(array_iterator, &value, &isnull)) {
        Datum old = result;
        result = edb::int4_add(old, value);
        pfree(DatumGetPointer(old));
    }

    Datum tmp = result;
    result =
        edb::int4_div(result, ArrayGetNItems(ARR_NDIM(array), ARR_DIMS(array)));
    pfree(DatumGetPointer(tmp));

    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(edb_int4_min_final);
Datum edb_int4_min_final(PG_FUNCTION_ARGS) {
    ArrayType *array = PG_GETARG_ARRAYTYPE_P(0);
    ArrayMetaState *extra =
        reinterpret_cast<ArrayMetaState *>(fcinfo->flinfo->fn_extra);
    ArrayIterator array_iterator = array_create_iterator(array, 0, extra);

    bool isnull;
    Datum result;

    array_iterate(array_iterator, &result, &isnull);

    Datum value;
    while (array_iterate(array_iterator, &value, &isnull)) {
        if (edb::int4_cmp(value, result) < 0)
            result = value;
    }

    PG_RETURN_BYTEA_P(DatumGetByteaPCopy(result));
}

PG_FUNCTION_INFO_V1(edb_int4_max_final);
Datum edb_int4_max_final(PG_FUNCTION_ARGS) {
    ArrayType *array = PG_GETARG_ARRAYTYPE_P(0);
    ArrayMetaState *extra =
        reinterpret_cast<ArrayMetaState *>(fcinfo->flinfo->fn_extra);
    ArrayIterator array_iterator = array_create_iterator(array, 0, extra);

    bool isnull;
    Datum result;

    array_iterate(array_iterator, &result, &isnull);

    Datum value;
    while (array_iterate(array_iterator, &value, &isnull)) {
        if (edb::int4_cmp(value, result) > 0)
            result = value;
    }

    PG_RETURN_BYTEA_P(DatumGetByteaPCopy(result));
}
}
