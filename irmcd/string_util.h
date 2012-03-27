#ifndef STRING_UTIL_H
#define STRING_UTIL_H

#define NSPLIT_ELEM_MAX 64

/* 簡易strlcpy                     *
 * 戻り値がない                    *
 * 関数仕様が変わっているのに注意  */
#define STRLCPY(dst, src, sz) 			\
do {						\
	strncpy((dst), (src), (sz) - 1);	\
	(dst)[(sz) - 1] = '\0';			\
} while (0)

/* 簡易strlcat                     *
 * 戻り値がない                    *
 * 関数仕様が変わっているのに注意  */
#define STRLCAT(dst, src, sz) 			\
do {						\
	strncat((dst), (src), (sz) - 1);	\
	(dst)[(sz) - 1] = '\0';			\
} while (0)

/*
 * 文字列をuint8に変換する
 */
int string_to_ui8(
    uint8_t *value,
    const char *str);

/*
 * 文字列をuint16に変換する
 */
int string_to_ui16(
    uint16_t *value,
    const char *str);

/*
 * 文字列をuint32に変換する
 */
int string_to_ui32(
    uint32_t *value,
    const char *str);

/*
 * 文字列をuint64に変換する
 */
int string_to_ui64(
    uint64_t *value,
    const char *str);

/*
 * 文字列をint8に変換する
 */
int string_to_i8(
    int8_t *value,
    const char *str);

/*
 * 文字列をint16に変換する
 */
int string_to_i16(
    int16_t *value,
    const char *str);

/*
 * 文字列をint32に変換する
 */
int string_to_i32(
    int32_t *value,
    const char *str);

/*
 * 文字列をint64に変換する
 */
int string_to_i64(
    int64_t *value,
    const char *str);

/*
 * 文字列をfloatに変換する
 */
int string_to_f(
    float *value,
    const char *str);

/*
 * 文字列をdoubleに変換する
 */
int string_to_d(
    double *value,
    const char *str);

/*
 * 文字列を置換する
 */
int string_replace(
    char *new,
    size_t new_size,
    const char *orig,
    const char *src,
    const char *dst);

/*
 * 元の文字列を変更する。
 * 破壊的メソッド郡 (関数名の最後のbはbrokenを意味する)
 */
struct kv_split {
    char *key;
    char *value;
};
typedef struct kv_split kv_split_t;

struct nsplit {
    int nelems;
    char *elems[NSPLIT_ELEM_MAX + 1];
};
typedef struct nsplit nsplit_t;

int string_lstrip_b(
    char **new_str,
    char *str,
    const char *strip_str);

int string_rstrip_b(
    char *str,
    const char *strip_str);

int string_kv_split_b(
    struct kv_split *kv_split,
    char *str,
    const char *delim_str);

int string_nsplit_b(
    struct nsplit *nsplit,
    char *str,
    const char *delim_str,
    int split_cnt,
    const char *splist_stop);

#endif
