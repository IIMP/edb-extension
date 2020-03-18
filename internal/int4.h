#ifndef EDB_INTERNAL_INT4_H_
#define EDB_INTERNAL_INT4_H_

extern "C" {
#include <postgres.h>
}

namespace edb {

int int4_cmp(Datum a, Datum b);

Datum int4_add(Datum a, Datum b);

Datum int4_sub(Datum a, Datum b);

Datum int4_mul(Datum a, Datum b);

Datum int4_div(Datum a, Datum b);

Datum int4_div(Datum a, int b);

Datum int4_mod(Datum a, Datum b);

Datum int4_pow(Datum a, Datum b);

} // namespace edb

#endif /* ifndef EDB_INTERNAL_INT4_H_ */
