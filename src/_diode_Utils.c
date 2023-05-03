#include <string.h>
#include <_diode_Main.h>
#include <_diode_Utils.h>

/* Function writes the given binary data (mem) to str as a base64 string.
 * It is the caller's responsability to make sure str has enough space for the binary data in b64 format + a null terminator
 * To find the b64 str size without the null terminator use _DIODE_BASE64STR_SIZE_FROM_NBYTES
 *
 * Error Codes:
 * -1 A NULL pointer was given as mem or str
 */
int_fast8_t _diode_BinaryToBase64Str(const uint_least8_t* const IN mem, uint_least32_t mem_size,
		uint_least8_t* const OUT str)
{
	if((!mem) | (!str))
	{
		_DIODE_DEBUG_PRINT("A NULL pointer was given!\n");
		return -1;
	}

	uint_least8_t remainder;
	uint_least8_t above0;
	uint_least8_t above1;
	uint_least8_t is1;
	int_fast32_t i;
	uint_fast32_t j;
	j = 0;
	i = 0;

	/* Read and copy four Base64 Binary values from three 8 bit binary values until there are less than three 8 bit values (word alignment) */
	while(i < (mem_size - 2))
	{
		str[j++] = (uint_least8_t)(mem[i]>>2);
		str[j++] = (uint_least8_t)((mem[i]&0x3)<<4) | (mem[i+1]>>4);
		str[j++] = (uint_least8_t)((mem[i+1]&0xF)<<2) | (mem[i+2]>>6);
		str[j++] = (uint_least8_t)(mem[i+2]&0x3F);
		i += 3;
	}

	/* If you can read this you deserve a medal */
	/* This does the shifting when necessary, puts in the '='(61) characters when necessary, and avoids reading memory out of bounds :) */
	i--;
	remainder = mem_size % 3;
	above0 = remainder > 0;
	above1 = remainder > 1;
	is1 = remainder & 1;
	str[j] = (uint_least8_t)(mem[i+above0]>>2)*above0;
	str[j + above0] = (uint_least8_t)((mem[i+above0]&0x3)<<4)*above0 | (mem[i+above0+above1]>>4)*above1;
	str[j + (above0<<1)] = (uint_least8_t)((mem[i+above0+above1]&0xF)<<2)*above1 | 61*is1;
	str[j + (above0*3)] = (uint_least8_t)61*above0;
	str[j + (above0<<2)] = (uint_least8_t)'\0';

	/* Convert Base64 binary values to Base64 chars in ascci/UTF-8 */
	i = ((mem_size/3)*4) + (above0<<1) + above1; /* Amount of Base64 chars to convert */
	do
	{
		i--;
		str[i] = (uint_least8_t)((str[i]<26)*(65+str[i])) |
			(((str[i]>25) & (str[i]<52))*(71+str[i])) |
			(((str[i]>51) & (str[i]<62))*(str[i]-4)) |
			((str[i]==62)*43) | ((str[i]==63)*47);
	} while(i);

	return 0;
}

/* Convertes a base64 string (str) to its binary representation, writing it in mem.
 * It is the Caller's responsability to ensure mem has anough space for the binary,
 * to find this necessary size for a given b64 string, you can use _diode_Base64StrSizeInBinaryBytes() or _diode_Base64StrSizeInBinaryBytes_wStrSize()
 * str_size is needed if the string is not null terminated, if it is, str_size must be 0 . The str_size must be a multiple of four.
 *
 * Error Codes:
 * -1 str_size isn't a multiple of 4
 * */
int_fast8_t _diode_Base64StrToBinary(const uint_least8_t* const IN str, uint_least8_t* const OUT mem, int_least32_t str_size)
{
	uint_fast32_t bytes;
	uint_fast8_t n_pads;
	uint_fast8_t c[4];
	uint_fast8_t is2;
	uint_fast8_t is1;
	uint_fast8_t above0;

	if(!str_size)
	{
		str_size = strlen((char*)str);
	}

	if(str_size % 4)
	{
		_DIODE_DEBUG_PRINT("Base64 String size isn't a multiple of 4!!!!! _diode_Base64StrToBinary() expects so.");
		return -1;
	}

	n_pads = (str[str_size-1] == '=') << (str[str_size-2] == '=');
	is2 = (n_pads > 1);
	is1 = (n_pads & 1);
	above0 = (n_pads > 0);
	bytes = (str_size / 4)*3 - n_pads - 1; /* 0 index ready */
	str_size = str_size - n_pads - 1; /* 0 index ready and minus the '=' chars */

	/* Base64 string to binary */
	/*The branching stays here as a comment for code readability, code below does the same
	if(n_pads & 1)
	{
		c[0] = (unsigned char)BASE64_TOBIN(str[str_size]); str_size--;
		c[1] = (unsigned char)BASE64_TOBIN(str[str_size]); str_size--;
		c[2] = (unsigned char)BASE64_TOBIN(str[str_size]); str_size--;
		mem[bytes--] = (unsigned char)(c[0] >> 2) | ((c[1]&0xF) << 4);
		mem[bytes--] = (unsigned char)(c[1] >> 4) | (c[2] << 2);
	}
	else if(n_pads)
	{
		c[0] = (unsigned char)BASE64_TOBIN(str[str_size]); str_size--;
		c[1] = (unsigned char)BASE64_TOBIN(str[str_size]); str_size--;
		mem[bytes--] = (unsigned char)(c[0] >> 4) | (c[1] << 2);
	}
	*/

	c[0] = (unsigned char)BASE64_TOBIN(str[str_size]);
	c[1] = (unsigned char)BASE64_TOBIN(str[str_size-1]);
	c[2] = BASE64_TOBIN(str[str_size-2]);
	str_size = str_size - ((above0<<1) | is1);

	mem[bytes-is1] = (c[1] >> 4) | (c[2] << 2);
	mem[bytes] = (c[0] >> ((above0 << is2)<<1)) | ( (c[1]&(0xF | (0xF0 * is2))) << ((is1<<2) | (is2<<1)) );
	bytes = bytes - (above0 << is1);

	/* Convert the remaining word aligned bytes */
	while(str_size > 0)
	{
		c[0] = (unsigned char)BASE64_TOBIN(str[str_size]); str_size--;
		c[1] = (unsigned char)BASE64_TOBIN(str[str_size]); str_size--;
		c[2] = (unsigned char)BASE64_TOBIN(str[str_size]); str_size--;
		c[3] = (unsigned char)BASE64_TOBIN(str[str_size]); str_size--;

		mem[bytes--] = (unsigned char)c[0] | ((c[1]&0x3) << 6);
		mem[bytes--] = (unsigned char)(c[1] >> 2) | ((c[2]&0xF) << 4);
		mem[bytes--] = (unsigned char)((c[2] >> 4)&3) | ((c[3]&0x3F) << 2);
	}

	return 0;
}


/* This function returns the amount of bytes (of 8bits size) necessary to represent the given string of base64.
 * If the string is not null terminated a size for the string must be given, otherwise size must be 0.
 * This funcion expects the string to be UTF8 / ASCCII.
 * This function expects the size to ALWAYS be a multiple of four.
 * Returns the amount of bytes needed to represent the base64 string in binary, or a negative error code
 *
 * Error Codes
 * -1 The given string size isn't a multiple of 4.
 */
int_least32_t _diode_AmountOfBytesFromB64Str(const uint_least8_t* const IN str, uint_least32_t size)
{
	if(!size)
		size = strlen((char*)str);

	if(size % 4)
	{
		_DIODE_DEBUG_PRINT("Given Base64 String size isn't a multiple of 4!!!!! _diode_AmountOfBytesFromB64Str() expects so.");
		return -1;
	}

	return (size / 4)*3 - ((str[size-1] == '=') + (str[size-2] == '='));
}
