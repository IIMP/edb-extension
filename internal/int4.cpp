#include "int4.h"

#include "enclave/bridge/enclave_u.h"
#include "internal.h"

namespace edb {

int int4_cmp(Datum a, Datum b) { return compare_value(a, b, ec_int4_cmp); }

Datum int4_add(Datum a, Datum b) { return do_math_op(a, b, ec_int4_add); }

Datum int4_sub(Datum a, Datum b) { return do_math_op(a, b, ec_int4_sub); }

Datum int4_mul(Datum a, Datum b) { return do_math_op(a, b, ec_int4_mul); }

Datum int4_div(Datum a, Datum b) { return do_math_op(a, b, ec_int4_div); }

Datum int4_mod(Datum a, Datum b) { return do_math_op(a, b, ec_int4_mod); }

Datum int4_pow(Datum a, Datum b) { return do_math_op(a, b, ec_int4_pow); }

Datum int4_div(Datum a, int b) { return do_math_op(a, b, ec_int4_div2); }

} // namespace edb
