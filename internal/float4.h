#ifndef EDB_INTERNAL_FLOAT4_H_
#define EDB_INTERNAL_FLOAT4_H_

extern "C" {
#include <postgres.h>
}

namespace edb {

int float4_cmp(Datum a, Datum b);

Datum float4_add(Datum a, Datum b);

Datum float4_sub(Datum a, Datum b);

Datum float4_mul(Datum a, Datum b);

Datum float4_div(Datum a, Datum b);

Datum float4_div(Datum a, float b);

Datum float4_mod(Datum a, Datum b);

Datum float4_pow(Datum a, Datum b);

} // namespace edb

#endif /* ifndef EDB_INTERNAL_FLOAT4_H_ */
