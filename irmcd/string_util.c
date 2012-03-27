#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#if defined(__linux__)
#include <values.h>
#elif defined(__FreeBSD__)
#include <float.h>
#endif
#include <math.h>

#include "string_util.h"

#ifndef LLONG_MAX
#define LLONG_MAX    LONG_MAX
#endif

#ifndef LLONG_MIN
#define LLONG_MIN    LONG_MIN
#endif

#ifndef ULLONG_MAX
#define ULLONG_MAX   ULONG_MAX
#endif

int
string_to_ui8(
    uint8_t *value,
    const char *str)
{
	unsigned long ul;
	char *ptr;

	if (value == NULL ||
	    str == NULL ||
	    *str == '\0') {
		errno = EINVAL;
		return 1;
	}
	errno = 0;
	ul = strtoul(str, &ptr, 0);
	if (*ptr !='\0' ||
	    (ul == 0 && errno == EINVAL) ||
	    (ul == ULONG_MAX && errno == ERANGE)) {
		*value = 0xff;
		return 1;
	}
	if (ul > UINT8_MAX) {
		errno = ERANGE;
		*value = 0xff;
		return 1;
	}
	*value = (uint8_t)ul;

	return 0;
}

int
string_to_ui16(
    uint16_t *value,
    const char *str)
{
	unsigned long ul;
	char *ptr;

	if (value == NULL ||
	    str == NULL ||
	    *str == '\0') {
		errno = EINVAL;
		return 1;
	}
	errno = 0;
	ul = strtoul(str, &ptr, 0);
	if (*ptr !='\0' ||
	    (ul == 0 && errno == EINVAL) ||
	    (ul == ULONG_MAX && errno == ERANGE)) {
		return 1;
	}
	if (ul > UINT16_MAX) {
		errno = ERANGE;
		return 1;
	}
	*value = (uint16_t)ul;

	return 0;
}

int
string_to_ui32(
    uint32_t *value,
    const char *str)
{
	unsigned long ul;
	char *ptr;

	if (value == NULL ||
	    str == NULL ||
	    *str == '\0') {
		errno = EINVAL;
		return 1;
	}
	errno = 0;
	ul = strtoul(str, &ptr, 0);
	if (*ptr !='\0' ||
	    (ul == 0 && errno == EINVAL) ||
	    (ul == ULONG_MAX && errno == ERANGE)) {
		return 1;
	}
	if (ul > UINT32_MAX) {
		errno = ERANGE;
		return 1;
	}
	*value = (uint32_t)ul;

	return 0;
}

int
string_to_ui64(
    uint64_t *value,
    const char *str)
{
	unsigned long long ull;
	char *ptr;

	if (value == NULL ||
	    str == NULL ||
	    *str == '\0') {
		errno = EINVAL;
		return 1;
	}
	errno = 0;
	ull = strtoull(str, &ptr, 0);
	if (*ptr !='\0' ||
	    (ull == 0 && errno == EINVAL) ||
	    (ull == ULLONG_MAX && errno == ERANGE)) {
		return 1;
	}
	if (ull > UINT64_MAX) {
		errno = ERANGE;
		return 1;
	}
	*value = (uint64_t)ull;

	return 0;
}

int
string_to_i8(
    int8_t *value,
    const char *str)
{
	long l;
	char *ptr;

	if (value == NULL ||
	    str == NULL ||
	    *str == '\0') {
		errno = EINVAL;
		return 1;
	}
	errno = 0;
	l = strtol(str, &ptr, 0);
	if (*ptr !='\0' ||
	    (l == 0 && errno == EINVAL) ||
	    (l == LONG_MIN && errno == ERANGE) ||
	    (l == LONG_MAX && errno == ERANGE)) {
		return 1;
	}
	if (l > INT8_MAX || l < INT8_MIN) {
		errno = ERANGE;
		return 1;
	}
	*value = (int8_t)l;

	return 0;
}

int
string_to_i16(
    int16_t *value,
    const char *str)
{
	long l;
	char *ptr;

	if (value == NULL ||
	    str == NULL ||
	    *str == '\0') {
		errno = EINVAL;
		return 1;
	}
	errno = 0;
	l = strtol(str, &ptr, 0);
	if (*ptr !='\0' ||
	    (l == 0 && errno == EINVAL) ||
	    (l == LONG_MIN && errno == ERANGE) ||
	    (l == LONG_MAX && errno == ERANGE)) {
		return 1;
	}
	if (l > INT16_MAX || l < INT16_MIN) {
		errno = ERANGE;
		return 1;
	}
	*value = (int16_t)l;

	return 0;
}

int
string_to_i32(
    int32_t *value,
    const char *str)
{
	long l;
	char *ptr;

	if (value == NULL ||
	    str == NULL ||
	    *str == '\0') {
		errno = EINVAL;
		return 1;
	}
	errno = 0;
	l = strtol(str, &ptr, 0);
	if (*ptr !='\0' ||
	    (l == 0 && errno == EINVAL) ||
	    (l == LONG_MIN && errno == ERANGE) ||
	    (l == LONG_MAX && errno == ERANGE)) {
		return 1;
	}
	if (l > INT32_MAX || l < INT32_MIN) {
		errno = ERANGE;
		return 1;
	}
	*value = (int32_t)l;

	return 0;
}

int
string_to_i64(
    int64_t *value,
    const char *str)
{
	long long ll;
	char *ptr;

	if (value == NULL ||
	    str == NULL ||
	    *str == '\0') {
		errno = EINVAL;
		return 1;
	}
	errno = 0;
	ll = strtoll(str, &ptr, 0);
	if (*ptr !='\0' ||
	    (ll == 0 && errno == EINVAL) ||
	    (ll == LLONG_MIN && errno == ERANGE) ||
	    (ll == LLONG_MAX && errno == ERANGE)) {
		return 1;
	}
	if (ll > INT64_MAX || ll < INT64_MIN) {
		errno = ERANGE;
		return 1;
	}
	*value = (int64_t)ll;

	return 0;
}

int
string_to_f(
    float *value,
    const char *str)
{
	double d;
	char *ptr;

	if (value == NULL ||
	    str == NULL ||
	    *str == '\0') {
		errno = EINVAL;
		return 1;
	}
	errno = 0;
	d = strtod(str, &ptr);
	if (*ptr !='\0' ||
	    ((d == HUGE_VAL && errno == ERANGE) ||
	     (d == -HUGE_VAL && errno == ERANGE))) {
		return 1;
	}
	if (d > FLT_MAX || d < FLT_MIN) {
		errno = ERANGE;
		return 1;
	}
	*value = (float)d;

	return 0;
}

int
string_to_d(
    double *value,
    const char *str)
{
	double d;
	char *ptr;

	if (value == NULL ||
	    str == NULL ||
	    *str == '\0') {
		errno = EINVAL;
		return 1;
	}
	errno = 0;
	d = strtod(str, &ptr);
	if (*ptr !='\0' ||
	    ((d == HUGE_VAL && errno == ERANGE) ||
	     (d == -HUGE_VAL && errno == ERANGE))) {
		return 1;
	}
	if (d > DBL_MAX || d < DBL_MIN) {
		errno = ERANGE;
		return 1;
	}
	*value = d;

	return 0;
}

int
string_replace(
    char *new,
    size_t new_size,
    const char *orig,
    const char *src,
    const char *dst)
{
	int orig_len;
	int src_len;
	int dst_len;
	const char *start;

	if (new == NULL ||
	    new_size == 0 ||
	    orig == NULL ||
	    src == NULL ||
	    dst == NULL) {
		errno = EINVAL;
		return -1;
	}
	orig_len = strlen(orig);
	src_len = strlen(src);
	dst_len = strlen(dst);
        if (orig_len < src_len) {
		strcpy(new, orig);
		return 1;
	}
	if (orig_len - src_len + dst_len >= new_size -1) {
		errno = ENOBUFS;
		return -1;
	}
	start = strstr(orig, src);
	if (start == NULL) {
		strcpy(new, orig);
		return 1;
	}
	strncpy(new, orig, (start - orig));
	strncpy(new + (start - orig), dst, dst_len);
	strncpy(
	   new + (start - orig) + dst_len,
	   start + src_len,
	   orig_len - ((start + src_len) - orig));
	new[orig_len - src_len + dst_len] = '\0';

	return 0;
}

int
string_lstrip_b(
    char **new_str,
    char *str,
    const char *strip_str)
{
        int len, last;
        char *find;

	if (new_str == NULL ||
	    str == NULL ||
	    strip_str == NULL) {
		return 1;
	}
        last = strlen(str);
	len = 0;
        while(len < last && str[len] != '\0') {
                find = strchr(strip_str, str[len]);
                if (find) {
                        str[len] = '\0';
                } else {
                        break;
                }
                len++;
        }
        *new_str = &str[len];

	return 0;
}

int
string_rstrip_b(
    char *str,
    const char *strip_str)
{
        int len;
        char *find;

	if (str == NULL || strip_str == NULL) {
		return 1;
	}
        len = strlen(str);
        while(len > 0  && str[len - 1] != '\0') {
                find = strchr(strip_str, str[len - 1]);
                if (find) {
                        str[len - 1] = '\0';
                } else {
                        break;
                }
                len--;
        }

	return 0;
}

int
string_kv_split_b(
    kv_split_t *kv,
    char *str,
    const char *delim_str)
{
	char *key;
	char *value;

	if (kv == NULL ||
	    str == NULL ||
	    delim_str == NULL) {
		return 1;
	}
	if (string_rstrip_b(str, "\r\n")) {
		return 1;
	}
	if ((key = strsep(&str, delim_str)) == NULL) {
		return 1;
	}
	if (string_rstrip_b(key, " \t")) {
		return 1;
	}
	if (string_lstrip_b(&value, str, " \t")) {
		return 1;
	}
	if (string_rstrip_b(value, " \t")) {
		return 1;
	}
	kv->key = key;
	kv->value = value;

	return 0;
}

int
string_nsplit_b(
    nsplit_t *nsplit,
    char *str,
    const char *delim_str,
    int split_cnt,
    const char *split_stop)
{
	char *src;
	char *next_src;
	char *elem;
	int i;
	int stop_len = 0;

	if (nsplit == NULL ||
	    str == NULL ||
	    split_cnt == 0) {
		return 1;
	}
	if (string_rstrip_b(str, "\r\n")) {
		return 1;
	}
	nsplit->nelems = 0; 
	if (split_cnt > NSPLIT_ELEM_MAX) {
		return 1;
	}
	if (split_stop != NULL) {
		stop_len = strlen(split_stop);
	}
	src = str;
	for (i = 0; i < split_cnt; i++) {
		if ((elem = strsep(&src, delim_str)) == NULL) {
			return 1;
		}
		if (src == NULL) {
			src = elem;
			break;
		}
		if (string_rstrip_b(elem, " \t")) {
			return 1;
		}
		if (string_lstrip_b(&next_src, src, " \t")) {
			return 1;
		}
		nsplit->elems[i] = elem;
		src = next_src;
		if (split_stop != NULL) {
			if (strncmp(src, split_stop, stop_len) == 0) {
				i++;
				break;
			}
		}
	}
	if (string_rstrip_b(src, " \t")) {
		return 1;
	}
	nsplit->elems[i] = src;
	nsplit->nelems = i + 1;

	return 0;
}
