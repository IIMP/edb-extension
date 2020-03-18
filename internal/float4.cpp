#include "float4.h"

#include "enclave/bridge/enclave_u.h"
#include "internal.h"

namespace edb {

int float4_cmp(Datum a, Datum b) { return compare_value(a, b, ec_float4_cmp); }

Datum float4_add(Datum a, Datum b) { return do_math_op(a, b, ec_float4_add); }

Datum float4_sub(Datum a, Datum b) { return do_math_op(a, b, ec_float4_sub); }

Datum float4_mul(Datum a, Datum b) { return do_math_op(a, b, ec_float4_mul); }

Datum float4_div(Datum a, Datum b) { return do_math_op(a, b, ec_float4_div); }

Datum float4_mod(Datum a, Datum b) { return do_math_op(a, b, ec_float4_mod); }

Datum float4_pow(Datum a, Datum b) { return do_math_op(a, b, ec_float4_pow); }

Datum float4_div(Datum a, float b) { return do_math_op(a, b, ec_float4_div2); }

} // namespace edb
