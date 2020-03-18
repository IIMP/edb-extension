extern "C" {
#include <postgres.h>

#include <fmgr.h>
}

#include "internal/internal.h"
#include "internal/text.h"

extern "C" {

PG_FUNCTION_INFO_V1(edb_text_in);
Datum edb_text_in(PG_FUNCTION_ARGS) {
    return edb::edb_value_in(PG_GETARG_DATUM(0));
}

PG_FUNCTION_INFO_V1(edb_text_out);
Datum edb_text_out(PG_FUNCTION_ARGS) {
    return edb::edb_value_out(PG_GETARG_DATUM(0));
}

PG_FUNCTION_INFO_V1(edb_text_eq);
Datum edb_text_eq(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::text_cmp(a, b);

    PG_RETURN_BOOL(ret == 0);
}

PG_FUNCTION_INFO_V1(edb_text_ne);
Datum edb_text_ne(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::text_cmp(a, b);

    PG_RETURN_BOOL(ret != 0);
}

PG_FUNCTION_INFO_V1(edb_text_le);
Datum edb_text_le(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::text_cmp(a, b);

    PG_RETURN_BOOL(ret <= 0);
}

PG_FUNCTION_INFO_V1(edb_text_lt);
Datum edb_text_lt(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::text_cmp(a, b);

    PG_RETURN_BOOL(ret < 0);
}

PG_FUNCTION_INFO_V1(edb_text_ge);
Datum edb_text_ge(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::text_cmp(a, b);

    PG_RETURN_BOOL(ret >= 0);
}

PG_FUNCTION_INFO_V1(edb_text_gt);
Datum edb_text_gt(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::text_cmp(a, b);

    PG_RETURN_BOOL(ret > 0);
}

PG_FUNCTION_INFO_V1(edb_text_cmp);
Datum edb_text_cmp(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    int ret = edb::text_cmp(a, b);

    PG_RETURN_INT32(ret);
}

PG_FUNCTION_INFO_V1(edb_text_concat);
Datum edb_text_concat(PG_FUNCTION_ARGS) {
    Datum a = PG_GETARG_DATUM(0);
    Datum b = PG_GETARG_DATUM(1);

    return edb::text_concat(a, b);
}

PG_FUNCTION_INFO_V1(edb_text_like);
Datum edb_text_like(PG_FUNCTION_ARGS) {
    Datum text = PG_GETARG_DATUM(0);
    Datum pattern = PG_GETARG_DATUM(1);

    PG_RETURN_BOOL(edb::text_match_like(text, pattern));
}

PG_FUNCTION_INFO_V1(edb_text_notlike);
Datum edb_text_notlike(PG_FUNCTION_ARGS) {
    Datum text = PG_GETARG_DATUM(0);
    Datum pattern = PG_GETARG_DATUM(1);

    PG_RETURN_BOOL(!edb::text_match_like(text, pattern));
}
}
