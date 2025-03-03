#ifndef __OPTION_H__
#define __OPTION_H__

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define PRINT (stderr)    

#define VERBOSE_KEY_M    TRUE
#define VERBOSE_ERROR    TRUE

#if VERBOSE_KEY_M
#define KEY_M_PRINT(fmt, args...) fprintf(PRINT, ""fmt"", ##args)
#else
#define KEY_M_PRINT(fmt, args...) (void)0
#endif

#if VERBOSE_ERROR
#define ERROR_PRINT(fmt, args...) fprintf(PRINT, ANSI_COLOR_GREEN \
                                    ""fmt""ANSI_COLOR_RESET, ##args)
#else
#define ERROR_PRINT(fmt, args...) (void)0
#endif

#define UNUSED(x) (void)(x)


/* Print message coloring */
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#endif /* __OPTION_H__ */