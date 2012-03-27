#ifndef LOGGER_H
#define LOGGER_H

/*
 *   logを出力する
 *   default動作ではファイルににログを書き出す
 *   １日毎にローテトする、古いファイルには日付が付く
 */
#define LOG_TYPE_STR_FILE	"file"
#define LOG_TYPE_STR_SYSLOG	"syslog"
#define LOG_TYPE_STR_STDERR	"stderr"
#define LOG_TYPE_STR_STDOUT	"stdout"

#define LOG_STR_DAEMON	"daemon"
#define LOG_STR_LOCAL0	"local0"
#define LOG_STR_LOCAL1	"local1"
#define LOG_STR_LOCAL2	"local2"
#define LOG_STR_LOCAL3	"local3"
#define LOG_STR_LOCAL4	"local4"
#define LOG_STR_LOCAL5	"local5"
#define LOG_STR_LOCAL6	"local6"
#define LOG_STR_LOCAL7	"local7"

enum log_level {
	LOG_LV_MIN	= 0,  	/* max */
	LOG_LV_EMERG	= 1,	/* system is unusable */
	LOG_LV_ALERT   	= 2,   	/* action must be taken immediately */
	LOG_LV_CRIT    	= 3,   	/* critical error conditions */
	LOG_LV_ERR     	= 4,   	/* error conditions */
	LOG_LV_WARNING 	= 5,   	/* warning conditions */
	LOG_LV_NOTICE  	= 6,   	/* normal but significant condition */
	LOG_LV_INFO    	= 7,   	/* informational */
	LOG_LV_DEBUG   	= 8,   	/* debug messages */
	LOG_LV_TRACE   	= 9,   	/* trace messages */
	LOG_LV_MAX	= 10,  	/* max */
};
typedef enum log_level log_level_t;

/*
 * ログを出力する
 * 即時出力
 */
int logging(
    log_level_t level,
    const char *fmt,
    ...);

/*
 * バイナリデータをダンプしつつログを出力する
 * 即時出力
 */
int logging_dump(
    log_level_t level,
    uint8_t *ptr,
    size_t len,
    const char *fmt,
    ...);

/*
 * ログをオープンする
 * 再オープンしたいときもlogger_openを呼ぶ
 */
int logger_open(
    log_level_t level,
    const char *type,
    const char *ident,
    int option,
    const char *facility,
    const char *logfile);

/*
 * ログをクローズする
 */
void logger_close(void);

/*
 * ログ コンテキストを作成する
 */
int logger_create(void);

/*
 * ログ コンテキストを削除する
 * もしクローズされていない場合は
 * 内部でlogger_closeを呼ぶ
 */
int logger_destroy(void);

/*
 * ログの出力レベルを変更する
 */
int logger_change_log_level(
    log_level_t level);

#endif
