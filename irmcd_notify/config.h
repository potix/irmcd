#ifndef CONFIG_H
#define CONFIG_H

/* 以下のようなフォーマットを読み込む *
 * [section]                          *
 * key=value                          *
 * thread safeではないので注意        */

#ifndef CONFIG_MAX_STR_LEN
#define CONFIG_MAX_STR_LEN 512
#endif
#define CONFIG_LINE_BUF ((CONFIG_MAX_STR_LEN + 1) * 2)

typedef struct config config_t;

/* configの生成 */
int config_create(
    config_t **config,
    const char *file_path);

/* configの削除 */
int config_destroy(
    config_t *config);

/*
 * コンフィグファイルの読み込み
 */
int config_load(
    config_t *config);

/*
 * string値の取得
 * 値が存在しない場合、default値を返す
 * default値がNULLで値が存在しない場合はエラーを返す
 */
int config_get_string(
    config_t *config,
    char *value,
    size_t value_size,
    const char *section,
    const char *key,
    const char *default_value,
    int max_str_len);

/*
 * int8値の取得
 * 値が存在しない場合、default値を返す
 * default値がNULLで値が存在しない場合はエラーを返す
 */
int config_get_int8(
    config_t *config,
    int8_t *value,
    const char *section,
    const char *key,
    char *default_value,
    int8_t min_value,
    int8_t max_value);

/*
 * uint8値の取得
 * 値が存在しない場合、default値を返す
 * default値がNULLで値が存在しない場合はエラーを返す
 */
int config_get_uint8(
    config_t *config,
    uint8_t *value,
    const char *section,
    const char *key,
    char *default_value,
    uint8_t min_value,
    uint8_t max_value);

/*
 * int16値の取得
 * 値が存在しない場合、default値を返す
 * default値がNULLで値が存在しない場合はエラーを返す
 */
int config_get_int16(
    config_t *config,
    int16_t *value,
    const char *section,
    const char *key,
    char *default_value,
    int16_t min_value,
    int16_t max_value);

/*
 * uint16値の取得
 * 値が存在しない場合、default値を返す
 * default値がNULLで値が存在しない場合はエラーを返す
 */
int config_get_uint16(
    config_t *config,
    uint16_t *value,
    const char *section,
    const char *key,
    char *default_value,
    uint16_t min_value,
    uint16_t max_value);

/*
 * int32値の取得
 * 値が存在しない場合、default値を返す
 * default値がNULLで値が存在しない場合はエラーを返す
 */
int config_get_int32(
    config_t *config,
    int32_t *value,
    const char *section,
    const char *key,
    const char *default_value,
    int32_t min_value,
    int32_t max_value);

/*
 * uint32値の取得
 * 値が存在しない場合、default値を返す
 * default値がNULLで値が存在しない場合はエラーを返す
 */
int config_get_uint32(
    config_t *config,
    uint32_t *value,
    const char *section,
    const char *key,
    const char *default_value,
    uint32_t min_value,
    uint32_t max_value);

/*
 * address値の取得
 * 値が存在しない場合、default値を返す
 * default値がNULLで値が存在しない場合はエラーを返す
 */
int config_get_address(
    config_t *config,
    char *value,
    size_t value_size,
    const char *section,
    const char *key,
    const char *default_value);

/*
 * port値の取得
 * 値が存在しない場合、default値を返す
 * default値がNULLで値が存在しない場合はエラーを返す
 */
int config_get_port(
    config_t *config,
    char *value,
    size_t value_size,
    const char *section,
    const char *key,
    const char *default_value);   

/*
 * bool値の取得
 * 値が存在しない場合、default値を返す
 * default値がNULLで値が存在しない場合はエラーを返す
 */
int config_get_bool(
    config_t *config,
    int *value,
    const char *section,
    const char *key,
    const char *default_value);

/*
 * sectionをforeachでまわし、callbckを呼ぶ
 * callbackが0以外を返した場合foreachを途中で抜ける
 */
int config_section_foreach(
    config_t *config,
    int (*foreach_cb)(config_t *config, const char *section, void *foreach_arg),
    void *foreach_arg);

#endif
