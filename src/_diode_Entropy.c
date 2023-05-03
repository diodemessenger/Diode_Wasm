#include <_diode_Entropy.h>
#include <stdlib.h>

/* This function returns an array of bytes of n_bytes size of entropy from JS crypto */
uint_least8_t* _diode_EntropyBytes_JS(uint_fast32_t n_bytes)
{
	return (uint_least8_t*) EM_ASM_INT({
		var rng = window.crypto || window.msCrypto;
		var entr = Array.from(rng.getRandomValues(new Uint8Array($0)));
		var c_array = Module._malloc($0);
		for (let i = 0; i < $0; i++)
		{
			Module.setValue(c_array + i, entr[i], "i8");
			entr[i] = 0;
		}
		return c_array;
	}, n_bytes);
}

uint_least8_t _diode_Entropy_JS(void)
{
	uint_least8_t* heap_byte = (uint_least8_t*) EM_ASM_INT({
		var rng = window.crypto || window.msCrypto;
		var entr = Array.from(rng.getRandomValues(new Uint8Array(1)));
		var c_array = Module._malloc(1);
		Module.setValue(c_array, entr[0], "i8");
		entr[0] = 0;
		return c_array;
	});

	uint_least8_t byte = *heap_byte;
	*heap_byte = 0;
	free(heap_byte);
	return byte;
}
