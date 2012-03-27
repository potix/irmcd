CFLAGS=-O2 -Wall -pipe  -D_REENTRANT -D_THREAD_SAFE -D_FILE_OFFSET_BITS=64 -D__USE_LARGEFILE64  -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs -Winline -Wuninitialized
all:
	gcc $(CFLAGS) -c irmcd_notify.c
	gcc $(CFLAGS) -c config.c
	gcc $(CFLAGS) -c string_util.c
	gcc -shared -fPIC -o irmcd_notify.jpi irmcd_notify.o config.o string_util.o
	echo "copy irmcd_notify.jpi and irmcd_notify.conf to julius plugin directory"
clean:
	rm -f irmcd_notify.jpi *.o
