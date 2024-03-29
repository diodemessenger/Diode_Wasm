#ifndef _DIODE_MAIN_H
#define _DIODE_MAIN_H

#include <emscripten.h>
#include <stdio.h>

/* Diode Project */
#define DIODE___

/* If emscripten isn't used */
#ifndef EMSCRIPTEN_KEEPALIVE
#define EMSCRIPTEN_KEEPALIVE /* nothing */
#endif

/* Code Readability defines */
#define OUT
#define IN

#define _DIODE_DEBUG_LVL 2

#if defined(_DIODE_DEBUG_LVL) && _DIODE_DEBUG_LVL
        #if _DIODE_DEBUG_LVL == 1
        #define _DIODE_DEBUG_PRINT(x, args...) fprintf(stdout,(x) "\n", ##args)
        #elif _DIODE_DEBUG_LVL == 2
                #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
                #define _DIODE_DEBUG_PRINT(x, args...) fprintf(stdout, "DEBUG: %s:%d:%s(): " "\n"x, \
                __FILE__, __LINE__, __func__, ##args)
                #else
                #define _DIODE_DEBUG_PRINT(x, args...) fprintf(stdout, "DEBUG: %s:%d():" "\n" x, \
                __FILE__, __LINE__, ##args)
                #endif
        #else
        #error("Invalid _DIODE_DEBUG_LVL!!!")
        #endif /* _DIODE_DEBUG_LVL */
#else
#define _DIODE_DEBUG_PRINT(x, args...)
#endif

extern int EMSCRIPTEN_KEEPALIVE _diode_Init();
extern int EMSCRIPTEN_KEEPALIVE _diode_Close();

#endif /* _DIODE_MAIN_H */
