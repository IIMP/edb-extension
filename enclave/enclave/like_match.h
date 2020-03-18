#ifndef EDB_LIKE_MATCH_H_
#define EDB_LIKE_MATCH_H_

#define LIKE_TRUE 1
#define LIKE_FALSE 0
#define LIKE_ABORT (-1)

#ifdef __cplusplus
extern "C" {
#endif

int match_text(char *, int, char *, int);

#ifdef __cplusplus
}
#endif

#endif
