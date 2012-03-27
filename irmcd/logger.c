#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>

#include "debug.h"
#include "logger.h"

#if defined(__linux__) && defined(__USE_LARGEFILE64)
#define FOPEN fopen64
#else
#define FOPEN fopen
#endif

#define DEFAULT_LOG_FACILITY    LOG_LOCAL1
#define DEFAULT_VERBOSE_LEVEL   LOG_INFO
#define VERBOSE_LEVEL_ALL       (LOG_MAX - 1)

#define LOG_PREFIX_BUFF         32
#define LOG_TIME_BUFF           64
#define LOG_HEAD_BUFF           128
#define LOG_MESG_BUFF           512
#define LOG_DUMP_BUFF           256

enum log_state {
        LOG_ST_NONE     = 0,
        LOG_ST_INIT     = 1,
        LOG_ST_OPENED   = 2,
        LOG_ST_CLOSED   = 3,
};
typedef enum log_state log_state_t;

enum log_type {
        LOG_TYPE_STDOUT = 0,
        LOG_TYPE_STDERR = 1,
        LOG_TYPE_SYSLOG = 2,
        LOG_TYPE_FILE   = 3,
};
typedef enum log_type log_type_t;

struct logger{
        int log_state;					/* log contextの状態を示す */
        log_level_t verbose_level;			/* verboseレベル */
        int log_type;					/* logの出力タイプ */
        FILE *log;					/*
							 * log fileのファイルポインタ
							 * 開いていない場合はNULL
							 */
        struct tm log_time;				/* 最新のログの出力時間 */
        char *logfilename;				/* logファイルの名前 */
        pid_t pid;					/* プロセス番号 */
        unsigned long long log_seq;			/* logにつけるシーケンス番号 */
        pthread_mutex_t logger_lock;			/* logのロック */
};
typedef struct logger logger_t;

static char logger_tag[LOG_LV_MAX][LOG_PREFIX_BUFF] = {
	"[UNKOWN]",	/* 0 */
	"[EMERG]",	/* 1 */
	"[ALERT]",	/* 2 */
	"[CRIT]",	/* 3 */
	"[ERROR]",	/* 4 */
	"[WARNING]",	/* 5 */
	"[NOTICE]",	/* 6 */
	"[INFO]",	/* 7 */
	"[DEBUG]",	/* 8 */
	"[TRACE]",	/* 9 */
};

logger_t *g_logger;

static int
logger_get_facility(
    const char *facility)
{
	if (facility == NULL) {
		return DEFAULT_LOG_FACILITY;
	}
	if (strcasecmp(facility, "daemon") == 0) {
		return LOG_DAEMON;
	} else if (strcasecmp(facility, "local0") == 0) {
		return LOG_LOCAL0;
	} else if (strcasecmp(facility, "local1") == 0) {
		return LOG_LOCAL1;
	} else if (strcasecmp(facility, "local2") == 0) {
		return LOG_LOCAL2;
	} else if (strcasecmp(facility, "local3") == 0) {
		return LOG_LOCAL3;
	} else if (strcasecmp(facility, "local4") == 0) {
		return LOG_LOCAL4;
	} else if (strcasecmp(facility, "local5") == 0) {
		return LOG_LOCAL5;
	} else if (strcasecmp(facility, "local6") == 0) {
		return LOG_LOCAL6;
	} else if (strcasecmp(facility, "local7") == 0) {
		return LOG_LOCAL7;
	} else {
		return DEFAULT_LOG_FACILITY;
	}
}

static void
logger_syslog_open(
    const char *ident,
    int option,
    const char *facility)
{
	int fac;
	const char *l_ident;

	l_ident = ident;
	fac = logger_get_facility(facility);
	openlog(l_ident, option|LOG_PID, fac);
}

static int
logger_get_mtime(
    const char *filename,
    time_t *m_time)
{
	struct stat sb;

	if (stat(filename, &sb)) {
		return 1;
	}
	*m_time = sb.st_mtime;

	return 0;
}

static int
logger_is_need_rotate(
    struct tm *cur_tm,
    struct tm *m_tm)
{
	if (cur_tm->tm_mday != m_tm->tm_mday ||
	    cur_tm->tm_mon != m_tm->tm_mon ||
	    cur_tm->tm_year != m_tm->tm_year) {
		return 1;
	}

	return 0;
}

static int
logger_get_rotatelogger_filename(
    char *filename,
    size_t filename_len,
    const char *prefix,
    struct tm *m_tm)
{
	snprintf(
	    filename,
	    filename_len,
	    "%s.%04d-%02d-%02d",
	    prefix,
	    (m_tm->tm_year + 1900),
	    (m_tm->tm_mon + 1),
	    (m_tm->tm_mday));

	return 0;
}

static int
logger_rotate(
    struct tm *cur_tm)
{
	char filename[MAXPATHLEN];
	char filename_rotate[MAXPATHLEN];
	FILE *fp;

	if (g_logger->log_type != LOG_TYPE_FILE) {
		return 0;
	}
	snprintf(filename, sizeof(filename), "%s", g_logger->logfilename);
	if (g_logger->log_state == LOG_ST_OPENED) {
		ASSERT(g_logger->log);
		if (logger_is_need_rotate(cur_tm, &g_logger->log_time)) {
			/* need rotate */
			logger_get_rotatelogger_filename(
			    filename_rotate,
			    sizeof(filename_rotate),
			    g_logger->logfilename,
			    &g_logger->log_time);
			fclose(g_logger->log);
			g_logger->log = NULL;
			g_logger->log_state = LOG_ST_CLOSED;
			if (rename(filename, filename_rotate)) {
				fprintf(
				    stderr,
				    "(%d) [ERROR] can not rename log file (%s -> %s)\n",
				    g_logger->pid,
				    filename,
				    filename_rotate);
			}
			fp = FOPEN(filename, "a+");
			if (fp == NULL) {
				fprintf(
				    stderr,
				    "(%d) [ERROR] can not open log file (%s)\n",
				    g_logger->pid,
				    filename);
				return 1;
			}
			g_logger->log_state = LOG_ST_OPENED;
			g_logger->log = fp;
		}
	} else {
		ASSERT(g_logger->log == NULL);
		fp = FOPEN(filename, "a+");
		if (fp == NULL) {
			fprintf(
			    stderr,
			    "(%d) [ERROR] can not open log file (%s)\n",
			    g_logger->pid,
			    filename);
			return 1;
		}
		g_logger->log_state = LOG_ST_OPENED;
		g_logger->log = fp;
	}

        return 0;
}

static int
logger_file_open(
    const char *logfile)
{
	time_t cur_time;
	time_t m_time;
        struct tm cur_tm;
        struct tm m_tm;
	const char *l_logfile;
        char filename[MAXPATHLEN];
        char filename_rotate[MAXPATHLEN];

	if (logfile == NULL) {
		fprintf(stderr,
		     "(%d) [ERROR] invalid log file path (%s)\n",
		     g_logger->pid,
		     logfile);
		return 1;
	} else {
		l_logfile = logfile;
	}
        snprintf(filename, sizeof(filename), "%s", l_logfile);
	cur_time = time(NULL);
	localtime_r(&cur_time, &cur_tm);

	/* ログファイルを新規に開く際に、過去のログがあり、*
         * 日付をまたいでいる場合は、rotateする            */
	if (logger_get_mtime(filename, &m_time) == 0) {
		localtime_r(&m_time, &m_tm);
		if (logger_is_need_rotate(&cur_tm, &m_tm)) {
			/* need rotate */
			logger_get_rotatelogger_filename(
			    filename_rotate,
			    sizeof(filename_rotate),
			    l_logfile,
			    &m_tm);
			if(rename(filename, filename_rotate)) {
				fprintf(
				    stderr,
				    "(%d) [ERROR] can not rename log file (%s -> %s)\n",
				    g_logger->pid,
				    filename,
				    filename_rotate);
			}
		}
	}
	g_logger->log = FOPEN(filename, "a+");
	if (g_logger->log == NULL) {
		fprintf(
		    stderr,
		    "(%d) [ERROR] can not open log file (%s)\n",
		    g_logger->pid,
		    filename);
		return 1;
	}
	g_logger->log_time = cur_tm;

	return 0;
}

static int
logger_get_syslog_log_level(
    log_level_t level)
{
	int lv;

	switch (level) {
	case LOG_LV_EMERG:
		lv = LOG_EMERG;
		break;
	case LOG_LV_ALERT:
		lv = LOG_ALERT;
		break;
	case LOG_LV_CRIT:
		lv = LOG_CRIT;
		break;
	case LOG_LV_ERR:
		lv = LOG_ERR;
		break;
	case LOG_LV_WARNING:
		lv = LOG_WARNING;
		break;
	case LOG_LV_NOTICE:
		lv = LOG_NOTICE;
		break;
	case LOG_LV_INFO:
		lv = LOG_INFO;
		break;
	case LOG_LV_DEBUG:
		lv = LOG_DEBUG;
		break;
	case LOG_LV_TRACE:
		lv = LOG_DEBUG;
		break;
	default:
		lv = LOG_DEBUG;
		break;
	}

	return lv;
}

static int
logging_base(
    log_level_t level,
    const char *fmt,
    va_list ap)
{
	char logtime[LOG_TIME_BUFF];
	char loghead[LOG_HEAD_BUFF];
	char logmesg[LOG_MESG_BUFF];
	time_t t;
	struct tm tm;

	ASSERT(g_logger != NULL);
	if (level > g_logger->verbose_level) {
		return 0;
	}
	vsnprintf(logmesg, sizeof(logmesg), fmt, ap);
	t = time(NULL);
	localtime_r(&t, &tm);
	strftime(logtime, sizeof(logtime), "%Y/%m/%d %H:%M:%S", &tm);
	if (pthread_mutex_lock(&g_logger->logger_lock)) {
		fprintf(stderr, "failed in lock of pthread in log print\n");
	}
	if (g_logger->verbose_level >= LOG_LV_DEBUG) {
		snprintf(
		    loghead,
		    sizeof(loghead),
		    "{%llu} (%d) %s <%m>",
		    g_logger->log_seq,
		    g_logger->pid,
		    logger_tag[level]);
	} else {
		snprintf(
		    loghead,
		    sizeof(loghead),
		    "{%llu} (%d) %s",
		    g_logger->log_seq,
		    g_logger->pid,
		    logger_tag[level]);
	}
	switch (g_logger->log_type) {
	case LOG_TYPE_FILE:
		if (g_logger->log_state == LOG_ST_OPENED) {
			if (logger_rotate(&tm)) {
				fprintf(
				    stderr,
				    "%s %s %s\n",
				    logtime,
				    loghead,
				    logmesg);
			} else {
				ASSERT(g_logger->log);
				fprintf(
				    g_logger->log,
				    "%s %s %s\n",
				    logtime,
				    loghead,
				    logmesg);
				fflush(g_logger->log);
			}
		} else {
			ASSERT(g_logger->log == NULL);
			fprintf(stderr, "%s %s %s\n", logtime, loghead, logmesg);
		}
		break;
	case LOG_TYPE_SYSLOG:
		syslog(
		    logger_get_syslog_log_level(level),
		    "%s %s %s\n",
		    logtime,
		    loghead,
		    logmesg);
		break;
	case LOG_TYPE_STDOUT:
		fprintf(stdout, "%s %s %s\n", logtime, loghead, logmesg);
		break;
	case LOG_TYPE_STDERR:
		fprintf(stderr, "%s %s %s\n", logtime, loghead, logmesg);
		break;
	default:
		fprintf(stderr, "%s %s %s\n", logtime, loghead, logmesg);
		break;
	}
	g_logger->log_time = tm;
	g_logger->log_seq++;
	if (pthread_mutex_unlock(&g_logger->logger_lock)) {
		fprintf(stderr, "failed in unlock of pthread in log print\n");
	}

	return 0;
}

static void
logging_dump_base(
    FILE *fp,
    log_level_t level,
    log_type_t type,
    const char *logtime,
    const char *loghead,
    const char *logmesg,
    u_int8_t *ptr,
    size_t len)
{
	char logbuf1[LOG_DUMP_BUFF] = "";
	char logbuf2[LOG_DUMP_BUFF] = "";
	char tmp[3];
	int i,j = 0;

	if (type != LOG_TYPE_SYSLOG) {
		fprintf(fp, "%s %s [DUMP: %s]\n", logtime, loghead, logmesg);
		fprintf(fp,"\n\t    0001 0203 0405 0607 0809 0a0b 0c0d 0e0f\n\n");
	} else {
		syslog(
		    logger_get_syslog_log_level(level),
		    "%s %s [DUMP: %s]\n",
		    logtime,
		    loghead,
		    logmesg);
		syslog(
		    logger_get_syslog_log_level(level),
		    "\t    0001 0203 0405 0607 0809 0a0b 0c0d 0e0f\n");
		syslog(logger_get_syslog_log_level(level), "\n");
	}
	for (i = 0; i < len; i++) {
		if (i % 16 == 0 && i != 0) {
			if (type != LOG_TYPE_SYSLOG) {
				fprintf(
				    fp,
				    "\t%02x  %-40s\t%s\n",
				    j++,
				    logbuf1,
				    logbuf2);
			} else {
				syslog(
				    logger_get_syslog_log_level(level),
				    "\t%02x  %-40s\t%s\n",
				    j++,
				    logbuf1,
				    logbuf2);
			}
			logbuf1[0] = '\0';
			logbuf2[0] = '\0';
		}
		snprintf(tmp, sizeof(tmp), "%02x", ptr[i]);
		strncat(logbuf1, tmp, sizeof(logbuf1) - (i * 2) - (i/2) - 1);
		if (isprint(ptr[i])) {
			snprintf(tmp, sizeof(tmp), "%c", (char)ptr[i]);
			strncat(logbuf2, tmp, sizeof(logbuf2) - i - 1);
		} else {
			strncat(logbuf2, ".", sizeof(logbuf2) - i - 1);
		}
		if (i % 2 != 0) {
			strncat(logbuf1, " ", sizeof(logbuf1) - (i * 2) - (i/2) - 1);
		}
	}
	if (type != LOG_TYPE_SYSLOG) {
		fprintf(fp,"\t%02x  %s\t%s\n\n", j, logbuf1, logbuf2);
	} else {
		syslog(
		    logger_get_syslog_log_level(level),
		    "\t%02x  %-40s\t%s\n",
		    j++,
		    logbuf1,
		    logbuf2);
		syslog(logger_get_syslog_log_level(level), "\n");
	}
}

int
logging(
    log_level_t level,
    const char *fmt,
    ...)
{
	va_list ap;

	ASSERT(g_logger != NULL);
	if (fmt == NULL || *fmt == '\0' ) {
		fprintf(
		    stderr,
		    "(%d) [ERROR] invalid log format of printing\n",
		    g_logger->pid);
		return 1;
	}
	va_start(ap, fmt);
	logging_base(level, fmt, ap);
	va_end(ap);

	return 0;
}

int
logging_dump(
    log_level_t level,
    u_int8_t *ptr,
    size_t len,
    const char *fmt,
    ...)
{
	va_list ap;
	char logtime[LOG_TIME_BUFF];
	char loghead[LOG_HEAD_BUFF];
	char logmesg[LOG_MESG_BUFF];
	time_t t;
	struct tm tm;

	ASSERT(g_logger != NULL);
	if (fmt == NULL || *fmt == '\0' ) {
		fprintf(
		    stderr,
		    "(%d) [ERROR] invalid log format of dumping\n",
		    g_logger->pid);
		return 1;
	}
        if (level > g_logger->verbose_level) {
		return 0;
	}
	va_start(ap, fmt);
        vsnprintf(logmesg, sizeof(logmesg), fmt, ap);
	va_end(ap);
	t = time(NULL);
	localtime_r(&t, &tm);
	strftime(logtime, sizeof(logtime), "%Y/%m/%d %H:%M:%S", &tm);
	if (pthread_mutex_lock(&g_logger->logger_lock)) {
		fprintf(stderr, "failed in lock of pthread in log dump\n");
	}
        snprintf(
	    loghead,
	    sizeof(loghead),
	    "{%llu} (%d) %s",
	    g_logger->log_seq,
	    g_logger->pid,
	    logger_tag[level]);
	switch (g_logger->log_type) {
	case LOG_TYPE_FILE:
		if (g_logger->log_state == LOG_ST_OPENED) {
			if (logger_rotate(&tm)) {
				logging_dump_base(
				    stderr,
				    level,
				    g_logger->log_type,
				    logtime,
				    loghead,
				    logmesg,
				    ptr,
				    len);
			} else {
				ASSERT(g_logger->log);
				logging_dump_base(
				    g_logger->log,
				    level,
				    g_logger->log_type,
				    logtime,
				    loghead,
				    logmesg,
				    ptr,
				    len);
				fflush(g_logger->log);
			}
		} else {
			ASSERT(g_logger->log == NULL);
			logging_dump_base(
			    stderr,
			    level,
			    g_logger->log_type,
			    logtime,
			    loghead,
			    logmesg,
			    ptr,
			    len);
		}
		break;
	case LOG_TYPE_SYSLOG:
		logging_dump_base(
		   stderr,
		   level,
		   g_logger->log_type,
		   logtime,
		   loghead,
		   logmesg,
		   ptr,
		   len);
		break;
	case LOG_TYPE_STDOUT:
		logging_dump_base(
		    stdout,
		    level,
		    g_logger->log_type,
		    logtime,
		    loghead,
		    logmesg,
		    ptr,
		    len);
		break;
	case LOG_TYPE_STDERR:
		logging_dump_base(
		    stderr,
		    level,
		    g_logger->log_type,
		    logtime,
		    loghead,
		    logmesg,
		     ptr,
		     len);
		break;
	default:
		logging_dump_base(
		    stderr,
		    level,
		    g_logger->log_type,
		    logtime,
		    loghead,
		    logmesg,
		    ptr,
		    len);
		break;
	}
	g_logger->log_time = tm;
	g_logger->log_seq++;
	if (pthread_mutex_unlock(&g_logger->logger_lock)) {
		fprintf(stderr, "failed in unlock of pthread in log dump\n");
	}

	return 0;
}

int
logger_open(
    log_level_t level,
    const char *type,
    const char *ident,
    int option,
    const char *facility,
    const char *logfile)
{
	int error = 0;
	int debuglog = 0;
	char *dup_logfile = NULL;

	ASSERT(g_logger != NULL);
	ASSERT(type != NULL);

	if (strcasecmp(type, "file") == 0 &&
	    (logfile == NULL || logfile[0] == '\0')) {
		errno = EINVAL;
		return 1;
	}
	if (logfile && logfile != '\0') {
		dup_logfile = strdup(logfile);
		if (dup_logfile == NULL) {
			return 1;
		}
	}
	if (pthread_mutex_lock(&g_logger->logger_lock)) {
		fprintf(stderr, "failed in lock of pthread in open log\n");
	}
	if (g_logger->log_state == LOG_ST_OPENED) {
		switch (g_logger->log_type) {
		case LOG_TYPE_FILE:
			if (g_logger->log == NULL) {
				fprintf(stderr,
				    "did not opened log file %s.",
				    g_logger->logfilename);
			} else {
				fclose(g_logger->log);
				g_logger->log = NULL;
			}
			free(g_logger->logfilename);
			g_logger->logfilename = NULL;
			g_logger->log_state = LOG_ST_CLOSED;
			break;
		case LOG_TYPE_SYSLOG:
			closelog();
			g_logger->log_state = LOG_ST_CLOSED;
			break;
		default:
			g_logger->log_state = LOG_ST_CLOSED;
			break;
		}
		g_logger->log_type = LOG_TYPE_STDERR;
	}
	if (strcasecmp(type, "file") == 0) {
		if (logger_file_open(dup_logfile)) {
			error = 1;
			goto last;
		}
		if (dup_logfile) {
			g_logger->logfilename = dup_logfile;
		}
		g_logger->log_type = LOG_TYPE_FILE;
		g_logger->log_state = LOG_ST_OPENED;
	} else if (strcasecmp(type, "syslog") == 0) {
		if (dup_logfile) {
			free(dup_logfile);
		}
		logger_syslog_open(ident, option, facility);
		g_logger->log_type = LOG_TYPE_SYSLOG;
		g_logger->log = NULL;
		g_logger->log_state = LOG_ST_OPENED;
	} else if (strcasecmp(type, "stdout") == 0) {
		if (dup_logfile) {
			free(dup_logfile);
		}
		g_logger->log_type = LOG_TYPE_STDOUT;
		g_logger->log = NULL;
		g_logger->log_state = LOG_ST_OPENED;
	} else {
		if (dup_logfile) {
			free(dup_logfile);
		}
		g_logger->log_type = LOG_TYPE_STDERR;
		g_logger->log = NULL;
		g_logger->log_state = LOG_ST_OPENED;
	}
	if (level > LOG_LV_MIN && level < LOG_LV_MAX) {
		g_logger->verbose_level = level;
	} else {
		g_logger->verbose_level = DEFAULT_VERBOSE_LEVEL;
	}
	g_logger->pid = getpid();
last:
	if (error) {
		free(dup_logfile);
	} else {
		if (g_logger->verbose_level >= LOG_LV_DEBUG) {
			debuglog = 1;
		}
	}
	if (pthread_mutex_unlock(&g_logger->logger_lock)) {
		fprintf(stderr, "failed in unlock of pthread in open log\n");
	}
	if (debuglog) {
		logging(
		    LOG_LV_DEBUG,
		    "logging info: type = %d, level %d, state %d, pid %d",
		    g_logger->log_type,
		    g_logger->verbose_level,
		    g_logger->log_state,
		    g_logger->pid);
	}

	return error;
}

void
logger_close(void)
{
	ASSERT(g_logger != NULL);

	if (pthread_mutex_lock(&g_logger->logger_lock)) {
		fprintf(stderr, "failed in lock of pthread in close log\n");
	}
	if (g_logger->log_state == LOG_ST_OPENED) {
		switch (g_logger->log_type) {
		case LOG_TYPE_FILE:
			if (g_logger->log == NULL) {
				fprintf(stderr,
				    "did not opened log file %s.",
				    g_logger->logfilename);
			} else {
				fclose(g_logger->log);
				g_logger->log = NULL;
			}
			free(g_logger->logfilename);
			g_logger->logfilename = NULL;
			g_logger->log_state = LOG_ST_CLOSED;
			break;
		case LOG_TYPE_SYSLOG:
			closelog();
			g_logger->log_state = LOG_ST_CLOSED;
			break;
		default:
			g_logger->log_state = LOG_ST_CLOSED;
			break;
		}
	}
	g_logger->log_type = LOG_TYPE_STDERR;
	if (pthread_mutex_unlock(&g_logger->logger_lock)) {
		fprintf(stderr, "failed in unlock of pthread in close log\n");
	}
}

int
logger_create(void)
{
	logger_t *new;

	if (g_logger != NULL) {
		errno = EINVAL;
		return 1;
	}
	new = malloc(sizeof(logger_t));
	if (new == NULL) {
		goto fail;
	}
	memset(new, 0, sizeof(logger_t));
	if (pthread_mutex_init(&new->logger_lock, NULL)) {
		goto fail;
	}
	new->log_type = LOG_TYPE_STDERR;
	new->log_state = LOG_ST_INIT;
	g_logger = new;

	return 0;

fail:
	free(new);
	return 1;
}

int
logger_destroy(void)
{
	if (g_logger == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (g_logger->log_state == LOG_ST_OPENED) {
		logger_close();
	}
	pthread_mutex_destroy(&g_logger->logger_lock);
	free(g_logger);
	g_logger = NULL;

	return 0;
}

int
logger_change_log_level(
    log_level_t level)
{
	if (g_logger == NULL) {
		errno = EINVAL;
		return 1;
	}
	g_logger->verbose_level = level;

	return 0;
}
