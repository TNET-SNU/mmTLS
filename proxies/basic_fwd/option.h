#ifndef __OPTION_H__
#define __OPTION_H__

#include "string.h"

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif

#define PRINT (stdout)

#define VERBOSE_MBUF        TRUE
#define VERBOSE_DPDK        FALSE
#define VERBOSE_TCP         TRUE
#define VERBOSE_RECV        TRUE
#define VERBOSE_SEND        FALSE

#define VERBOSE_STAT        FALSE
#define VERBOSE_DEBUG       TRUE
#define VERBOSE_ERROR       TRUE

#if VERBOSE_DPDK
#define DPDK_PRINT(fmt, args...) fprintf(PRINT,""fmt"", ##args)
#else
#define DPDK_PRINT(fmt, args...) (void)0
#endif
#if VERBOSE_TCP
#define TCP_PRINT(fmt, args...) fprintf(PRINT,""fmt"", ##args)
#else
#define TCP_PRINT(fmt, args...) (void)0
#endif
#if VERBOSE_DEBUG
#define DEBUG_PRINT(fmt, args...) fprintf(PRINT,""fmt"", ##args)
#else
#define DEBUG_PRINT(fmt, args...) (void)0
#endif
#if VERBOSE_ERROR
#define ERROR_PRINT(fmt, args...) fprintf(PRINT,ANSI_COLOR_GREEN \
								  ""fmt""ANSI_COLOR_RESET, ##args)
#else
#define ERROR_PRINT(fmt, args...) (void)0
#endif
#define UNUSED(x)           (void)(x)


#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif /* likely */

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif /* unlikely */

#ifdef dmb
#undef dmb
#endif /* dmb */

#define USE_LRO                          TRUE
#define USE_HASHTABLE_FOR_ACTIVE_SESSION TRUE

/** Options for debug */
#define DEBUG_FLAG                       0
#define MODIFY_FLAG                      1

/* Print message coloring */
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define MAX_THREAD_NUM 16

#endif /* __OPTION_H__ */
