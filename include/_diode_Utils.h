#ifndef _DIODE_UTILS_H
#define _DIODE_UTILS_H

#include <stdint.h>

/* This macro assumes there can't be an odd amount of nibbles representing a key,
 * returns base64 string size to represent the amount of data in bytes (size) given, without the null terminator */
#define _DIODE_BASE64STR_SIZE_FROM_NBYTES(size) ((((size) / 3)*4) + ((((size) % 3) > 0)<<2))

#define VAL_TO_HEX_CHAR(x) ( (((x)+48)*((x) < 10)) | (((x)+55)*((x) > 9)) )

#define BASE64_TOBIN(x) (uint_least8_t)(((x) > 96)*((x) - 71) | \
			((((x)>64) & (uint_least8_t)((x)<91))*((x) - 65)) | \
			((((x)>47) & (uint_least8_t)((x)<58))*((x) + 4)) | \
			(((x)=='+')*62) | (((x)=='/')*63))


/* This function returns the amount of bytes (of 8bits size) necessary to represent the given string of base64.
 * If the string is not null terminated a size for the string must be given, otherwise size must be 0. 
 * This funcion expects the string to be UTF8 / ASCCII.
 * This function expects the size to ALWAYS be a multiple of four.
 * Returns the amount of bytes needed to represent the base64 string in binary, or a negative error code
 *
 * Error Codes
 * -1 The given string size isn't a multiple of 4.
 */
extern int_least32_t _diode_AmountOfBytesFromB64Str(const uint_least8_t* const IN str, const uint_least32_t size);

/* Convertes a base64 string (str) to its binary representation, writing it in mem.
 * It is the Caller's responsability to ensure mem has anough space for the binary,
 * to find this necessary size for a given b64 string, you can use _diode_Base64StrSizeInBinaryBytes() or _diode_Base64StrSizeInBinaryBytes_wStrSize()
 * str_size is needed if the string is not null terminated, if it is, str_size must be 0 . The str_size must be a multiple of four.
 * */
extern int_fast8_t _diode_Base64StrToBinary(const uint_least8_t* const IN str, uint_least8_t* const OUT mem, int_least32_t str_size);

/* Function writes the given binary data (mem) to str as a base64 string.
 * It is the caller's responsability to make sure str has enough space for the binary data in b64 format + a null terminator
 * To find the b64 str size without the null terminator use _DIODE_BASE64STR_SIZE_FROM_NBYTES
 *
 * Error Codes:
 * -1 A NULL pointer was given as mem or str
 */
extern int_fast8_t _diode_BinaryToBase64Str(const uint_least8_t* const IN mem, uint_least32_t mem_size,
		uint_least8_t* const OUT str);


#endif /* _DIODE_UTILS_H */
