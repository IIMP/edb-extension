#ifndef EDB_INTERNAL_TEXT_H_
#define EDB_INTERNAL_TEXT_H_

extern "C" {
#include <postgres.h>
}

namespace edb {

int text_cmp(Datum a, Datum b);

Datum text_concat(Datum a, Datum b);

Datum text_match_like(Datum text, Datum pattern);

} // namespace edb
#endif /* ifndef EDB_INTERNAL_TEXT_H_ */
