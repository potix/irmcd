bin_PROGRAMS = irmcd
irmcd_SOURCES = irmcd.c config.c string_util.c tcp_sock.c queue.c buffer_manager.c controller.c logger.c config.h string_util.h tcp_sock.h queue.h buffer_manager.h controller.h logger.h debug.h
irmcd_LDFLAGS = -levent -lpcre
irmcd_CFLAGS = -O2 -Wall -pipe  -D_REENTRANT -D_THREAD_SAFE -D_FILE_OFFSET_BITS=64 -D__USE_LARGEFILE64  -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs -Winline -Wuninitialized
