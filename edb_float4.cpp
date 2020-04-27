extern "C" {
#include <postgres.h>

#include <fmgr.h>
#include <utils/array.h>
}

#include "utils/float.h"

#include "internal/float4.h"
#include "internal/internal.h"

extern "C" {

#ifdef DEBUG_MODE
float4 pg_float4_in(char* num)
{

    char* orig_num;
    double val;
    char* endptr;

    /*
     * endptr points to the first character _after_ the sequence we recognized
     * as a valid floating point number. orig_num points to the original input
     * string.
     */
    orig_num = num;

    /* skip leading whitespace */
    while (*num != '\0' && isspace((unsigned char)*num))
        num++;

    /*
     * Check for an empty-string input to begin with, to avoid the vagaries of
     * strtod() on different platforms.
     */
    if (*num == '\0')
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                 errmsg("invalid input syntax for type %s: \"%s\"",
                        "real", orig_num)));

    errno = 0;
    val = strtod(num, &endptr);

    /* did we not see anything that looks like a double? */
    if (endptr == num || errno != 0)
    {
        int save_errno = errno;

        /*
         * C99 requires that strtod() accept NaN, [+-]Infinity, and [+-]Inf,
         * but not all platforms support all of these (and some accept them
         * but set ERANGE anyway...)  Therefore, we check for these inputs
         * ourselves if strtod() fails.
         *
         * Note: C99 also requires hexadecimal input as well as some extended
         * forms of NaN, but we consider these forms unportable and don't try
         * to support them.  You can use 'em if your strtod() takes 'em.
         */
        if (pg_strncasecmp(num, "NaN", 3) == 0)
        {
            val = get_float4_nan();
            endptr = num + 3;
        }
        else if (pg_strncasecmp(num, "Infinity", 8) == 0)
        {
            val = get_float4_infinity();
            endptr = num + 8;
        }
        else if (pg_strncasecmp(num, "+Infinity", 9) == 0)
        {
            val = get_float4_infinity();
            endptr = num + 9;
        }
        else if (pg_strncasecmp(num, "-Infinity", 9) == 0)
        {
            val = -get_float4_infinity();
            endptr = num + 9;
        }
        else if (pg_strncasecmp(num, "inf", 3) == 0)
        {
            val = get_float4_infinity();
            endptr = num + 3;
        }
        else if (pg_strncasecmp(num, "+inf", 4) == 0)
        {
            val = get_float4_infinity();
            endptr = num + 4;
        }
        else if (pg_strncasecmp(num, "-inf", 4) == 0)
        {
            val = -get_float4_infinity();
            endptr = num + 4;
        }
        else if (save_errno == ERANGE)
        {
            /*
             * Some platforms return ERANGE for denormalized numbers (those
             * that are not zero, but are too close to zero to have full
             * precision).  We'd prefer not to throw error for that, so try to
             * detect whether it's a "real" out-of-range condition by checking
             * to see if the result is zero or huge.
             */
            if (val == 0.0 || val >= HUGE_VAL || val <= -HUGE_VAL)
                ereport(ERROR,
                        (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                         errmsg("\"%s\" is out of range for type real",
                                orig_num)));
        }
        else
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                     errmsg("invalid input syntax for type %s: \"%s\"",
                            "real", orig_num)));
    }
#ifdef HAVE_BUGGY_SOLARIS_STRTOD
    else
    {
        /*
         * Many versions of Solaris have a bug wherein strtod sets endptr to
         * point one byte beyond the end of the string when given "inf" or
         * "infinity".
         */
        if (endptr != num && endptr[-1] == '\0')
            endptr--;
    }
#endif /* HAVE_BUGGY_SOLARIS_STRTOD */

    /* skip trailing whitespace */
    while (*endptr != '\0' && isspace((unsigned char)*endptr))
        endptr++;

    /* if there is any junk left at the end of the string, bail out */
    if (*endptr != '\0')
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                 errmsg("invalid input syntax for type %s: \"%s\"",
                        "real", orig_num)));

    /*
     * if we get here, we have a legal double, still need to check to see if
     * it's a legal float4
     */
    //CHECKFLOATVAL((float4) val, isinf(val), val == 0);

    return ((float4)val);
}

PG_FUNCTION_INFO_V1(edb_float4_in);
Datum edb_float4_in(PG_FUNCTION_ARGS) {
    float4 num = pg_float4_in(PG_GETARG_CSTRING(0));
    
    return edb::edb_value_in((const char *)&num, sizeof(float4));
}

PG_FUNCTION_INFO_V1(edb_float4_out);
Datum edb_float4_out(PG_FUNCTION_ARGS) {
    bytea *data = PG_GETARG_BYTEA_PP(0);
    size_t data_size = VARSIZE_ANY_EXHDR(data);

    return edb::edb_value_out(VARDATA(data), data_size);
}
#else
PG_FUNCTION_INFO_V1(edb_float4_in);
Datum edb_float4_in(PG_FUNCTION_ARGS) {
    return edb::edb_value_in(PG_GETARG_DATUM(0));
}

PG_FUNCTION_INFO_V1(edb_float4_out);
Datum edb_float4_out(PG_FUNCTION_ARGS) {
    return edb::edb_value_out(PG_GETARG_DATUM(0));
}
#endif

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
