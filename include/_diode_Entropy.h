#ifndef _DIODE_ENTROPY_H
#define _DIODE_ENTROPY_H

#include <_diode_Main.h>

#include <stdint.h>
#include <emscripten.h>

/* This function returns an array of bytes of n_bytes size of entropy from JS rng */
extern uint_least8_t* _diode_EntropyBytes_JS(uint_fast32_t n_bytes);
extern void _diode_EntropyBytes_noAlloc_JS(uint_least8_t* mem, uint_fast32_t n_bytes);
extern uint_least8_t _diode_Entropy_JS(void);


#endif /* _DIODE_ENTROPY_H */
