extern "C" {
#include <postgres.h>

#include <fmgr.h>
#include <utils/array.h>
}

#include "internal/float4.h"
#include "internal/internal.h"

extern "C" {

PG_FUNCTION_INFO_V1(edb_float4_in);
Datum edb_float4_in(PG_FUNCTION_ARGS) {
    return edb::edb_value_in(PG_GETARG_DATUM(0));
}

PG_FUNCTION_INFO_V1(edb_float4_out);
Datum edb_float4_out(PG_FUNCTION_ARGS) {
    return edb::edb_value_out(PG_GETARG_DATUM(0));
}

PG_FUNCTION_INFO_V1(edb_float4_eq);
Datum edb_float4_eq(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::float4_cmp(a, b);

    PG_RETURN_BOOL(ret == 0);
}

PG_FUNCTION_INFO_V1(edb_float4_ne);
Datum edb_float4_ne(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::float4_cmp(a, b);

    PG_RETURN_BOOL(ret != 0);
}

PG_FUNCTION_INFO_V1(edb_float4_lt);
Datum edb_float4_lt(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::float4_cmp(a, b);

    PG_RETURN_BOOL(ret < 0);
}

PG_FUNCTION_INFO_V1(edb_float4_le);
Datum edb_float4_le(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::float4_cmp(a, b);

    PG_RETURN_BOOL(ret <= 0);
}

PG_FUNCTION_INFO_V1(edb_float4_gt);
Datum edb_float4_gt(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::float4_cmp(a, b);

    PG_RETURN_BOOL(ret > 0);
}

PG_FUNCTION_INFO_V1(edb_float4_ge);
Datum edb_float4_ge(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::float4_cmp(a, b);

    PG_RETURN_BOOL(ret >= 0);
}

PG_FUNCTION_INFO_V1(edb_float4_cmp);
Datum edb_float4_cmp(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::float4_cmp(a, b);

    PG_RETURN_INT32(ret);
}

PG_FUNCTION_INFO_V1(edb_float4_add);
Datum edb_float4_add(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::float4_add(a, b);
}

PG_FUNCTION_INFO_V1(edb_float4_sub);
Datum edb_float4_sub(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::float4_sub(a, b);
}

PG_FUNCTION_INFO_V1(edb_float4_mul);
Datum edb_float4_mul(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::float4_mul(a, b);
}

PG_FUNCTION_INFO_V1(edb_float4_div);
Datum edb_float4_div(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::float4_div(a, b);
}

PG_FUNCTION_INFO_V1(edb_float4_mod);
Datum edb_float4_mod(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::float4_mod(a, b);
}

PG_FUNCTION_INFO_V1(edb_float4_pow);
Datum edb_float4_pow(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::float4_pow(a, b);
}

PG_FUNCTION_INFO_V1(edb_float4_sum_final);
Datum edb_float4_sum_final(PG_FUNCTION_ARGS) {
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
        result = edb::float4_add(old, value);
        pfree(DatumGetPointer(old));
    }

    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(edb_float4_avg_final);
Datum edb_float4_avg_final(PG_FUNCTION_ARGS) {
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
        result = edb::float4_add(old, value);
        pfree(DatumGetPointer(old));
    }

    Datum tmp = result;
    result = edb::float4_div(result, static_cast<float>(ArrayGetNItems(
                                         ARR_NDIM(array), ARR_DIMS(array))));
    pfree(DatumGetPointer(tmp));

    PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(edb_float4_min_final);
Datum edb_float4_min_final(PG_FUNCTION_ARGS) {
    ArrayType *array = PG_GETARG_ARRAYTYPE_P(0);
    ArrayMetaState *extra =
        reinterpret_cast<ArrayMetaState *>(fcinfo->flinfo->fn_extra);
    ArrayIterator array_iterator = array_create_iterator(array, 0, extra);

    bool isnull;
    Datum result;

    array_iterate(array_iterator, &result, &isnull);

    Datum value;
    while (array_iterate(array_iterator, &value, &isnull)) {
        if (edb::float4_cmp(value, result) < 0)
            result = value;
    }

    PG_RETURN_BYTEA_P(DatumGetByteaPCopy(result));
}

PG_FUNCTION_INFO_V1(edb_float4_max_final);
Datum edb_float4_max_final(PG_FUNCTION_ARGS) {
    ArrayType *array = PG_GETARG_ARRAYTYPE_P(0);
    ArrayMetaState *extra =
        reinterpret_cast<ArrayMetaState *>(fcinfo->flinfo->fn_extra);
    ArrayIterator array_iterator = array_create_iterator(array, 0, extra);

    bool isnull;
    Datum result;

    array_iterate(array_iterator, &result, &isnull);

    Datum value;
    while (array_iterate(array_iterator, &value, &isnull)) {
        if (edb::float4_cmp(value, result) > 0)
            result = value;
    }

    PG_RETURN_BYTEA_P(DatumGetByteaPCopy(result));
}
}
