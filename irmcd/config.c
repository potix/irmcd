#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "debug.h"
#include "logger.h"
#include "string_util.h"
#include "config.h"

typedef struct config_param config_param_t;
typedef struct config_section config_section_t;

struct config_param {
	char *key;
	char *value;
	TAILQ_ENTRY(config_param) next;
};

struct config_section {
	char *section;
	TAILQ_HEAD(config_param_head, config_param) config_param_head;
	int nparams;
	TAILQ_ENTRY(config_section) next;
};

struct config {
	char *file_path;
	TAILQ_HEAD(config_section_head, config_section) config_section_head;
	int nsecntions;
};

static config_section_t *
find_config_section(
    config_t *config,
    const char *section)
{
	config_section_t *config_section;

	ASSERT(config != NULL);
	ASSERT(section != NULL);
	TAILQ_FOREACH(config_section, &config->config_section_head, next) {
		if (strcmp(section, config_section->section) == 0) {
			return config_section;
		}
	}

	return NULL; 
}

static config_param_t *
find_config_param_from_config_section(
    config_section_t *config_section,
    const char *key)
{
	config_param_t *config_param;

	ASSERT(config_section != NULL);
	ASSERT(key != NULL);
	TAILQ_FOREACH(config_param, &config_section->config_param_head, next) {
		if (strcmp(key, config_param->key) == 0) {
			return config_param;
		}
	}

	return NULL;
}

static config_param_t *
find_config_param(
    config_t *config,
    const char *section,
    const char *key)
{
	config_section_t *config_section;
	config_param_t *config_param;

	ASSERT(section != NULL);
	ASSERT(key != NULL);
	config_section = find_config_section(config, section);
	if (config_section == NULL) {
		return NULL;
	}
	config_param = find_config_param_from_config_section(config_section, key);
	if (config_param == NULL) {
		return NULL;
	}

	return config_param; 
}

static void
config_clear(
    config_t *config)
{
	config_section_t *config_section, *config_section_next;
	config_param_t *config_param, *config_param_next;

	ASSERT(config != NULL);
	config_section = TAILQ_FIRST(&config->config_section_head);
	while (config_section) {
		config_section_next = TAILQ_NEXT(config_section, next);
		TAILQ_REMOVE(&config->config_section_head, config_section, next);
		config_param = TAILQ_FIRST(&config_section->config_param_head);
		while (config_param) {
			config_param_next = TAILQ_NEXT(config_param, next);
			TAILQ_REMOVE(&config_section->config_param_head, config_param, next);
			free(config_param->key);
			free(config_param->value);
			free(config_param);
			config_param = config_param_next;
		}
		free(config_section->section);
		free(config_section);
		config_section = config_section_next;
	}
}

static int
config_parse(
    config_t *config,
    FILE *fp)
{
	config_section_t *config_section = NULL;
	config_section_t *new_config_section;
	config_param_t *config_param;
	config_param_t *new_config_param;
	kv_split_t kv;
	char line[CONFIG_LINE_BUF];
	char *line_ptr;
	int linecnt = 0;
	char *tmp_value;

	ASSERT(config != NULL);
	ASSERT(fp != NULL);
	while (1) {
		if (fgets(line, sizeof(line), fp) == NULL) {
			break;
		}
		linecnt++;
		if (string_lstrip_b(&line_ptr, line, " \t")) {
			logging(
			    LOG_LV_ERR,
			    "failed in lstrip in %s (line = %d)",
			    __func__,
			    linecnt);
			return 1;
		}
		if (string_rstrip_b(line_ptr, " \t\r\n")) {
			logging(
			    LOG_LV_ERR,
			    "failed in rstrip in %s (line = %d)",
			    __func__,
			    linecnt);
			return 1;
		}
		if (*line_ptr == '\0' ||
		    *line_ptr == '#') {
			continue;
		}
		if (*line_ptr == '[' && line_ptr[strlen(line_ptr) - 1] == ']') {
			line_ptr[strlen(line_ptr) - 1] = '\0';
			line_ptr++;
			if (string_lstrip_b(&line_ptr, line_ptr, " \t")) {
				logging(
				    LOG_LV_ERR,
				    "failed in lstrip in %s (line = %d)",
				    __func__,
				    linecnt);
				return 1;
			}
			if (string_rstrip_b(line_ptr, " \t\r\n")) {
				logging(
				    LOG_LV_ERR,
				    "failed in rstrip in %s (line = %d)",
				    __func__,
				    linecnt);
				return 1;
			}
			config_section = find_config_section(config, line_ptr);
			if (!config_section) {
				new_config_section = malloc(sizeof(config_section_t));
				if (!new_config_section) {
					logging(
					    LOG_LV_ERR,
					    "failed in allocate memory in %s (line = %d)",
					    __func__,
					    linecnt);
					goto fail;
				}
				new_config_section->section = NULL;
				TAILQ_INIT(&new_config_section->config_param_head);
				TAILQ_INSERT_TAIL(
				    &config->config_section_head,
				    new_config_section,
				    next);
				new_config_section->section = strdup(line_ptr);
				if (new_config_section->section == NULL) {
					logging(
					    LOG_LV_ERR,
					    "failed in allocate memory in %s (line = %d)",
					    __func__,
					    linecnt);
					goto fail;
				}
				config_section = new_config_section;
			}
			continue;
		} 
		if (string_kv_split_b(&kv, line_ptr, "=")) {
			logging(
			    LOG_LV_WARNING,
			    "failed in split key and value in %s (line = %d)",
			    __func__,
			    linecnt);
			continue;
		} else {
			if (!config_section) {
				logging(
				    LOG_LV_WARNING,
				    "not found section in %s (line = %d)",
				    __func__,
				    linecnt);
				continue;
			}
			config_param =
			    find_config_param_from_config_section(
			    config_section,
			    kv.key);
			if (!config_param) {
				new_config_param = malloc(sizeof(config_param_t));
				if (!new_config_param) {
					logging(
					    LOG_LV_ERR,
					    "failed in allocate memory in %s (line = %d)",
					    __func__,
					    linecnt);
					goto fail;
				}
				new_config_param->key = NULL;
				new_config_param->value = NULL;
				TAILQ_INSERT_TAIL(
				    &config_section->config_param_head,
				    new_config_param,
				    next);
				new_config_param->key = strdup(kv.key);
				if (!new_config_param->key) {
					logging(
					    LOG_LV_ERR,
					    "failed in allocate memory in %s (line = %d)",
					    __func__,
					    linecnt);
					goto fail;
				}
				new_config_param->value = strdup(kv.value);
				if (!new_config_param->value) {
					logging(
					    LOG_LV_ERR,
					    "failed in allocate memory in %s (line = %d)",
					    __func__,
					    linecnt);
					goto fail;
				}
				config_param = new_config_param;
			} else {
				tmp_value = strdup(kv.value);
				if (tmp_value == NULL) {
					logging(
					    LOG_LV_ERR,
					    "failed in allocate memory in %s (line = %d)",
					    __func__,
					    linecnt);
					goto fail;
				}
				free(config_param->value);
				config_param->value = tmp_value;
			}
		}
	}
	
	return 0;

fail:

	config_clear(config);

	return 1;
}

int
config_create(
    config_t **config,
    const char *file_path)
{
	config_t *new = NULL;
	char *copy_file_path = NULL;

	if (config == NULL ||
	    file_path == NULL) {
		errno = EINVAL;
		return 1;
	}
	new = malloc(sizeof(config_t));
	if (new == NULL) {
		errno = ENOBUFS;
		goto fail;
	}
	memset(new, 0, sizeof(config_t));
	copy_file_path = strdup(file_path);
	if (copy_file_path == NULL) {
		errno = ENOBUFS;
		goto fail;
	}
	TAILQ_INIT(&new->config_section_head);
	new->file_path = copy_file_path;
	*config = new;

	return 0;

fail:
	free(copy_file_path);
	free(new);

	return 1; 
}


int
config_destroy(
    config_t *config)
{
	if (config == NULL) {
		errno = EINVAL;
		return 1;
	}
	config_clear(config);
	free(config->file_path);
	free(config);

	return 0;
}

int
config_load(
    config_t *config)
{
        FILE *fp = NULL;
	int error = 0;

	if (config == NULL ||
	    config->file_path[0] == '\0') {
		errno = EINVAL;
		return 1;
	}
        fp = fopen(config->file_path, "r");
        if (fp == NULL) {
		logging(LOG_LV_ERR, "failed open config file (%s)", config->file_path);
                error = 1;
		goto final;
        }
	if (config_parse(config, fp)) {
		logging(LOG_LV_ERR, "parse error");
                error = 1;
		goto final;
	}
final:
	if (fp != NULL) {
		fclose(fp);
	}
	if (error) {
		return 1;
	}

	return 0;
}

int
config_get_string(
    config_t *config,
    char *value,
    size_t value_size,
    const char *section,
    const char *key,
    const char *default_value,
    int max_str_len)
{
	config_param_t *config_param;
	const char *v;
	int value_len;
	
	if (config == NULL ||
	    value == NULL ||
	    value_size == 0 ||
	    section == NULL ||
	    key == NULL ||
	    max_str_len <= 0) {
		errno = EINVAL;
		return 1;
	}
	config_param = find_config_param(config, section, key);
	if (config_param == NULL) {
		if (default_value == NULL) {
			errno = ENOENT;
			return 1;
		}
		v = default_value;
	} else {
		v = config_param->value;
	}
	value_len = strlen(v);
	if (value_size  < value_len + 1) {
		errno = ENOBUFS;
		logging(LOG_LV_ERR, "not enough buffer in %s", __func__);
		return 1;
	}
	if (max_str_len < value_len) {
		errno = EINVAL;
		logging(LOG_LV_ERR, "too long param");
		return 1;
	}
	STRLCPY(value, v, value_size);

	return 0;
}

int
config_get_int8(
    config_t *config,
    int8_t *value,
    const char *section,
    const char *key,
    char *default_value,
    int8_t min_value,
    int8_t max_value)
{
	config_param_t *config_param;
	const char *v;
	int8_t tmp;

	if (config == NULL ||
	    value == NULL ||
	    section == NULL ||
	    key == NULL ||
	    default_value == NULL) {
		errno = EINVAL;
		return 1;
	}
	config_param = find_config_param(config, section, key);
	if (config_param == NULL) {
		if (default_value == NULL) {
			errno = ENOENT;
			return 1;
		}
		v = default_value;
	} else {
		v = config_param->value;
	}
	if (string_to_i8(&tmp, v)) {
		logging(LOG_LV_ERR, "failed in convert");
		errno = EINVAL;
		return 1;
	}
	if (min_value > tmp || max_value < tmp) {
		logging(LOG_LV_ERR, "out of range");
		errno = ERANGE;
		return 1;
	}
	*value = tmp;

	return 0;
}

int
config_get_uint8(
    config_t *config,
    uint8_t *value,
    const char *section,
    const char *key,
    char *default_value,
    uint8_t min_value,
    uint8_t max_value)
{
	config_param_t *config_param;
	const char *v;
	uint8_t tmp;

	if (config == NULL ||
	    value == NULL ||
	    section == NULL ||
	    key == NULL ||
	    default_value == NULL) {
		errno = EINVAL;
		return 1;
	}
	config_param = find_config_param(config, section, key);
	if (config_param == NULL) {
		if (default_value == NULL) {
			errno = ENOENT;
			return 1;
		}
		v = default_value;
	} else {
		v = config_param->value;
	}
	if (string_to_ui8(&tmp, v)) {
		logging(LOG_LV_ERR, "failed in convert");
		errno = EINVAL;
		return 1;
	}
	if (min_value > tmp || max_value < tmp) {
		logging(LOG_LV_ERR, "out of range");
		errno = ERANGE;
		return 1;
	}
	*value = tmp;

	return 0;
}

int
config_get_int16(
    config_t *config,
    int16_t *value,
    const char *section,
    const char *key,
    char *default_value,
    int16_t min_value,
    int16_t max_value)
{
	config_param_t *config_param;
	const char *v;
	int16_t tmp;

	if (config == NULL ||
	    value == NULL ||
	    section == NULL ||
	    key == NULL ||
	    default_value == NULL) {
		errno = EINVAL;
		return 1;
	}
	config_param = find_config_param(config, section, key);
	if (config_param == NULL) {
		if (default_value == NULL) {
			errno = ENOENT;
			return 1;
		}
		v = default_value;
	} else {
		v = config_param->value;
	}
	if (string_to_i16(&tmp, v)) {
		logging(LOG_LV_ERR, "failed in convert");
		errno = EINVAL;
		return 1;
	}
	if (min_value > tmp || max_value < tmp) {
		logging(LOG_LV_ERR, "out of range");
		errno = ERANGE;
		return 1;
	}
	*value = tmp;

	return 0;
}

int
config_get_uint16(
    config_t *config,
    uint16_t *value,
    const char *section,
    const char *key,
    char *default_value,
    uint16_t min_value,
    uint16_t max_value)
{
	config_param_t *config_param;
	const char *v;
	uint16_t tmp;

	if (config == NULL ||
	    value == NULL ||
	    section == NULL ||
	    key == NULL ||
	    default_value == NULL) {
		errno = EINVAL;
		return 1;
	}
	config_param = find_config_param(config, section, key);
	if (config_param == NULL) {
		if (default_value == NULL) {
			errno = ENOENT;
			return 1;
		}
		v = default_value;
	} else {
		v = config_param->value;
	}
	if (string_to_ui16(&tmp, v)) {
		logging(LOG_LV_ERR, "failed in convert");
		errno = EINVAL;
		return 1;
	}
	if (min_value > tmp || max_value < tmp) {
		logging(LOG_LV_ERR, "out of range");
		errno = ERANGE;
		return 1;
	}
	*value = tmp;

	return 0;
}

int
config_get_int32(
    config_t *config,
    int32_t *value,
    const char *section,
    const char *key,
    const char *default_value,
    int32_t min_value,
    int32_t max_value)
{
	config_param_t *config_param;
	const char *v;
	int32_t tmp;

	if (config == NULL ||
	    value == NULL ||
	    section == NULL ||
	    key == NULL ||
	    default_value == NULL) {
		errno = EINVAL;
		return 1;
	}
	config_param = find_config_param(config, section, key);
	if (config_param == NULL) {
		if (default_value == NULL) {
			errno = ENOENT;
			return 1;
		}
		v = default_value;
	} else {
		v = config_param->value;
	}
	if (string_to_i32(&tmp, v)) {
		logging(LOG_LV_ERR, "failed in convert");
		errno = EINVAL;
		return 1;
	}
	if (min_value > tmp || max_value < tmp) {
		logging(LOG_LV_ERR, "out of range");
		errno = ERANGE;
		return 1;
	}
	*value = tmp;

	return 0;
}

int
config_get_uint32(
    config_t *config,
    uint32_t *value,
    const char *section,
    const char *key,
    const char *default_value,
    uint32_t min_value,
    uint32_t max_value)
{
	config_param_t *config_param;
	const char *v;
	uint32_t tmp;

	if (config == NULL ||
	    value == NULL ||
	    section == NULL ||
	    key == NULL ||
	    default_value == NULL) {
		errno = EINVAL;
		return 1;
	}
	config_param = find_config_param(config, section, key);
	if (config_param == NULL) {
		if (default_value == NULL) {
			errno = ENOENT;
			return 1;
		}
		v = default_value;
	} else {
		v = config_param->value;
	}
	if (string_to_ui32(&tmp, v)) {
		logging(LOG_LV_ERR, "failed in convert");
		errno = EINVAL;
		return 1;
	}
	if (min_value > tmp || max_value < tmp) {
		logging(LOG_LV_ERR, "out of range");
		errno = ERANGE;
		return 1;
	}
	*value = tmp;

	return 0;
}

int
config_get_address(
    config_t *config,
    char *value,
    size_t value_size,
    const char *section,
    const char *key,
    const char *default_value)
{
	struct addrinfo addr_info_hints, *addr_info_res, *addr_info_res0;
	int i = 0;

	if (config_get_string(
	    config,
	    value,
	    value_size,
	    section,
	    key,
	    default_value,
	    (NI_MAXHOST > value_size) ? value_size : NI_MAXHOST)) {
		return 1;
	}
	memset(&addr_info_hints, 0, sizeof(addr_info_hints));
	if (getaddrinfo(value, NULL, &addr_info_hints, &addr_info_res0)) {
		logging(LOG_LV_ERR, "failed in get address information (%s)", value);
		*value = '\0';
		return 1;
	} else {
		for (addr_info_res = addr_info_res0;
		     addr_info_res;
		     addr_info_res = addr_info_res->ai_next) {
			i++;
		}
		freeaddrinfo(addr_info_res0);
		if (i == 0) {
			logging(LOG_LV_ERR, "no address entry");
			errno = ENOENT;
			*value = '\0';
			return 1;
		}
	}

	return 0;
}

int
config_get_port(
    config_t *config,
    char *value,
    size_t value_size,
    const char *section,
    const char *key,
    const char *default_value)
{
	struct addrinfo addr_info_hints, *addr_info_res, *addr_info_res0;
	int i = 0;
	char sbuf[NI_MAXSERV];
	uint16_t tmp;

	if (config_get_string(
	    config,
	    value,
	    value_size,
	    section,
	    key,
	    default_value,
	    (NI_MAXSERV > value_size) ? value_size : NI_MAXSERV)) {
		return 1;
	}
	memset(&addr_info_hints, 0, sizeof(addr_info_hints));
	if (getaddrinfo(NULL, value, &addr_info_hints, &addr_info_res0)) {
		logging(LOG_LV_ERR, "failed in get port information");
		*value = '\0';
		return 1;
	} else {
		for (addr_info_res = addr_info_res0;
		     addr_info_res;
		     addr_info_res = addr_info_res->ai_next) {
			if(getnameinfo(
			    addr_info_res->ai_addr,
			    addr_info_res->ai_addrlen,
			    NULL, 0,
			    sbuf, sizeof(sbuf),
			    NI_NUMERICSERV)) {
				continue;
			}
			i++;
		}
		freeaddrinfo(addr_info_res0);
		if (i == 0) {
			logging(LOG_LV_ERR, "no port entry");
			errno = ENOENT;
			*value = '\0';
			return 1;
		}
		if (string_to_ui16(&tmp, sbuf)) {
			logging(LOG_LV_ERR, "failed in convert");
			errno = EINVAL;
			*value = '\0';
			return 1;
		}
		if (1 > tmp || 65535 < tmp) {
			logging(LOG_LV_ERR, "out of range");
			errno = ERANGE;
			*value = '\0';
			return 1;
		}
	}

	return 0;
}

int
config_get_bool(
    config_t *config,
    int *value,
    const char *section,
    const char *key,
    const char *default_value)
{
	config_param_t *config_param;
	const char *v;
	int tmp;

	if (config == NULL ||
	    value == NULL ||
	    section == NULL ||
	    key == NULL) {
		errno = EINVAL;
		return 1;
	}
	config_param = find_config_param(config, section, key);
	if (config_param == NULL) {
		if (default_value == NULL) {
			errno = ENOENT;
			return 1;
		}
		v = default_value;
	} else {
		v = config_param->value;
	}
	if (strcasecmp(v, "on") == 0 ||
	    strcasecmp(v, "true") == 0) {
		tmp = 1;
	} else if (strcasecmp(v, "off") == 0 ||
	    strcasecmp(v, "false") == 0) {
		tmp = 0;
	} else {
		errno = EINVAL;
		return 1;
	}
	*value = tmp;

	return 0;
}

int
config_section_foreach(
    config_t *config,
    int (*foreach_cb)(config_t *config, const char *section, void *foreach_arg),
    void *foreach_arg) 
{
	config_section_t *config_section;

	if (config == NULL ||
	    foreach_cb == NULL) {
		errno = EINVAL;
		return 1;
	}
	TAILQ_FOREACH(config_section, &config->config_section_head, next) {
		if (foreach_cb(config, config_section->section, foreach_arg)) {
			break;
		}
	}
	return 0;
}

