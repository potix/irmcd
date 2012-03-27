#ifndef DEBUG_H
#define DEBUG_H

#define IRMCD_DEBUG

#ifdef IRMCD_DEBUG
#define ASSERT(x)                       \
do {                                    \
        if (!(x)) {                     \
                fprintf(stderr,         \
                    "assert %s:%d",     \
                     __func__,          \
                     __LINE__);         \
                abort();                \
        }                               \
} while(0)
#define ABORT(msg)                                      \
do {                                                    \
        fprintf(stderr, msg " - abort %s:%d:%m",        \
             __func__, __LINE__);                       \
        abort();                                        \
} while(0)
#else
#define ASSERT(x)
#define ABORT(msg)
#endif

#endif
