#include <_diode_Main.h>
#include <_diode_Keygen.h>
#include <crypto_kem_mceliece460896f.h>

#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Defines for code readability */
#define IN
#define OUT

int main(void)
{
	/*
	_diode_Init();
	unsigned char* msg = (unsigned char*) "Hello Wasm!";

	uint_least32_t pub_chars, prv_chars, out_chars, secret_chars, n_chars, e_chars, d_chars;
	unsigned char** prv_str = malloc(sizeof(*prv_str));
	unsigned char** pub_str = malloc(sizeof(*pub_str));

	unsigned char** rsa_n = malloc(sizeof(*rsa_n));
	unsigned char** rsa_e = malloc(sizeof(*rsa_e));
	unsigned char** rsa_d = malloc(sizeof(*rsa_d));

	unsigned char** out_str = malloc(sizeof(*out_str));
	unsigned char** secret_str = malloc(sizeof(*secret_str));

	_diode_ED25519_Keygen(pub_str, &pub_chars, prv_str, &prv_chars);

	printf("PUB chars: %d | PRV chars: %d\n", pub_chars, prv_chars);
	printf("PUB ED25519 KEY: %s\n", *pub_str);
	printf("PRV ED25519 KEY: %s\n", *prv_str);

	uint_least8_t* dig = _diode_SignString_wED25519PrivateBase64Key(msg, 0, *prv_str);
	if(dig == NULL)
		return -1;

	printf("Digest: %s\n", dig);
	printf("Verify Success? : %d\n", _diode_VerifySig_wED25519PublicBase64Key(dig, *pub_str, msg));

	puts("Now RSA!\n");

	if(_diode_RSA_Keygen(rsa_n, &n_chars, rsa_e, &e_chars, rsa_d, &d_chars, 4096))
	{
		return 1;
	}

	printf("PARAM N chars: %d | PARAM E chars: %d | PARAM D chars: %d\n", n_chars, e_chars, d_chars);
	printf("RSA N PARAM: %s\n", *rsa_n);
	printf("RSA E PARAM: %s\n", *rsa_e);
	printf("RSA D PARAM: %s\n", *rsa_d);

	puts("Now Encapsulation!\n");

	if(_diode_RSA_encapsulate(*rsa_n, 0, *rsa_e, 0, out_str, &out_chars, secret_str, &secret_chars))
	{
		return 1;
	}

	printf("OUT chars: %d | SECRET chars: %d\n", out_chars, secret_chars);
	printf("OUT   : %s\n", *out_str);
	printf("SECRET: %s\n", *secret_str);
	
	free(*rsa_n); free(*rsa_e); free(*rsa_d);
	free(rsa_n); free(rsa_e); free(rsa_d);
	free(*out_str);
	free(*secret_str);
	free(out_str);
	free(secret_str);


	free(*prv_str);
	free(*pub_str);	
	puts("Now McEliece Key Generation\n");

	_diode_mceliece460896f_Keygen(pub_str, &pub_chars, prv_str, &prv_chars);
	printf("PUB chars: %d | PRV chars: %d\n", pub_chars, prv_chars);
	printf("PUB McEliece KEY: %s\n", *pub_str);
	printf("PRV McEliece KEY: %s\n", *prv_str);

	free(*prv_str);
	free(*pub_str);
	free(prv_str);
	free(pub_str);

	_diode_Close();


	*/
	printf("main() is done!\n\n");
	return 0;
}


int EMSCRIPTEN_KEEPALIVE _diode_Init()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	return 0;
}

int EMSCRIPTEN_KEEPALIVE _diode_Close()
{
	ENGINE_cleanup();
	CONF_modules_unload(1);
	EVP_cleanup();
	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
	CRYPTO_cleanup_all_ex_data();

	return 0;
}


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


#define BASE64_TOBIN(x) (uint_least8_t)(((x) > 96)*((x) - 71) | \
			((((x)>64) & (uint_least8_t)((x)<91))*((x) - 65)) | \
			((((x)>47) & (uint_least8_t)((x)<58))*((x) + 4)) | \
			(((x)=='+')*62) | (((x)=='/')*63))

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

/* This function Generates a random pair of RSA Keys, where the n and e parameters are the public key and the d parameter is the private key.
 * bits determines the bit size, must be a multiple of 1024 or 0 for default of 2048 bits.
 * *rsa_n_str, rsa_e_str and rsa_d_str will hold the n,e,d parameters in b64 format.
 * These strings will be NULL terminated, but if you wish you can provide rsa_n_chars, rsa_e_chars, rsa_d_chars,
 * where the size of the b64 parameter stirngs in b64 chars will be written to *rsa_n_chars, *rsa_e_chars and *rsa_d_chars.
 * If you don't wish to know the sizes, NULL can be given rsa_n_chars, rsa_e_chars and rsa_d_chars.
 *
 * Error Codes:
 * -1  A NULL pointer was given for one of the string pointers.
 * -2  RSA bit size must be a multiple of 1024.
 * -3  Couldn't create EVP_PKEY_CTX object for RSA.
 * -4  Couldn't initialize key context object for RSA.
 * -5  Couldn't set parameters for key context object for RSA.
 * -6  Couldn't generate RSA keys.
 * -7  Couldn't create EVP_PKEY object, RSA keys couldn't be generated.
 * -8  Couldn't allocate the memory for the n, e or d RSA parameter BIGNUM object.
 * -9  Couldn't extract RSA n parameter.
 * -10 Couldn't extract RSA e parameter.
 * -11 Couldn't extract RSA d parameter.
 * -12 Couldn't allocate the memory for the RSA n, e or d parameter binary.
 * -13 Didn't copy the correct size of bytes from the n, e or d paramter BIGNUM to binary buffer.
 * -14 Couldn't allocate memory for rsa_n_chars, rsa_e_chars or rsa_d_chars.
 * -15 Couldn't allocate memory for n parameter string.
 * -16 Couldn't convert n parameter binary to base64.
 * -17 Couldn't allocate memory for e parameter string.
 * -18 Couldn't convert e parameter binary to base64.
 * -19 Couldn't allocate memory for d parameter string.
 * -20 Couldn't convert d parameter binary to base64.
 */
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_Keygen(uint_least8_t** OUT rsa_n_str, uint_least32_t* rsa_n_chars,
		uint_least8_t** OUT rsa_e_str, uint_least32_t* rsa_e_chars,
		uint_least8_t** OUT rsa_d_str, uint_least32_t* rsa_d_chars,
		uint_least32_t bits)
{
	if((!rsa_n_str) | (!rsa_e_str) | (!rsa_d_str))
	{
		_DIODE_DEBUG_PRINT("A NULL pointer was given for one of the string pointers!\n");
		return -1;
	}

	if(bits % 1024)
	{
		_DIODE_DEBUG_PRINT("RSA bit size must be a multiple of 1024!");
		return -2;
	}

	if(!bits)
		bits = 2048;

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if(!ctx)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_PKEY_CTX object for RSA!\n");
		return -3;
	}

	if(EVP_PKEY_keygen_init(ctx) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't initialize key context object for RSA!\n");
		EVP_PKEY_CTX_free(ctx);
		return -4;
	}

	unsigned int n_primes = 2;
	OSSL_PARAM params[3];
	params[0] = OSSL_PARAM_construct_uint("bits", &bits);
	params[1] = OSSL_PARAM_construct_uint("primes", &n_primes);
	params[2] = OSSL_PARAM_construct_end();
	
	if(!EVP_PKEY_CTX_set_params(ctx, params))
	{
		_DIODE_DEBUG_PRINT("Couldn't set parameters for key context object for RSA!\n");
		EVP_PKEY_CTX_free(ctx);
		return -5;
	}

	EVP_PKEY* keys;
	if(EVP_PKEY_generate(ctx, &keys) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't generate RSA keys!\n");
		EVP_PKEY_CTX_free(ctx);
		return -6;
	}

	if(!keys)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_PKEY object, RSA keys couldn't be generated!\n");
		EVP_PKEY_CTX_free(ctx);
		return -7;
	}

	/* EVP_PKEY_print_public_fp(stdout, keys, 2, NULL); */

	/* Now let's get BIGNUM parameters of RSA */
	BIGNUM *BN_n, *BN_e, *BN_d;

	BN_n = BN_new();
	if(!BN_n)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the n RSA parameter BIGNUM object!\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(keys);
		return -8;
	}
	BN_e = BN_new();
	if(!BN_e)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the e RSA parameter BIGNUM object!\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(keys);
		BN_free(BN_n);
		return -8;
	}
	BN_d = BN_new();
	if(!BN_d)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the d RSA parameter BIGNUM object!\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(keys);
		BN_free(BN_n); BN_free(BN_e);
		return -8;
	}
	
	if(!EVP_PKEY_get_bn_param(keys, "n", &BN_n))
	{
		_DIODE_DEBUG_PRINT("Couldn't extract RSA n parameter!\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(keys);
		BN_free(BN_n); BN_free(BN_e); BN_free(BN_d);
		return -9;
	}
	if(!EVP_PKEY_get_bn_param(keys, "e", &BN_e))
	{
		_DIODE_DEBUG_PRINT("Couldn't extract RSA e parameter!\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(keys);
		BN_clear_free(BN_n); BN_free(BN_e); BN_free(BN_d);
		return -10;
	}
	if(!EVP_PKEY_get_bn_param(keys, "d", &BN_d))
	{
		_DIODE_DEBUG_PRINT("Couldn't extract RSA d parameter!\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(keys);
		BN_clear_free(BN_n); BN_clear_free(BN_e); BN_free(BN_d);
		return -11;
	}
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(keys);

	/* Now let's get the binary from the BIGNUM's */
	size_t rsa_n_size, rsa_e_size, rsa_d_size;

	/* Getting lenght sizes, this assumes the word size is a multiple of the bit lenght of these parameters*/
	rsa_n_size = BN_num_bytes(BN_n);
	rsa_e_size = BN_num_bytes(BN_e);
	rsa_d_size = BN_num_bytes(BN_d);

	uint_least8_t* rsa_n_mem = malloc(rsa_n_size);
	if(!rsa_n_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the RSA n parameter binary!\n");
		BN_clear_free(BN_n); BN_clear_free(BN_e); BN_clear_free(BN_d);
		return -12;
	}
	uint_least8_t* rsa_e_mem = malloc(rsa_e_size);
	if(!rsa_n_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the RSA e parameter binary!\n");
		BN_clear_free(BN_n); BN_clear_free(BN_e); BN_clear_free(BN_d);
		free(rsa_n_mem);
		return -12;
	}
	uint_least8_t* rsa_d_mem = malloc(rsa_d_size);
	if(!rsa_d_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the RSA d parameter binary!\n");
		BN_clear_free(BN_n); BN_clear_free(BN_e); BN_clear_free(BN_d);
		free(rsa_n_mem); free(rsa_e_mem);
		return -12;
	}

	if(BN_bn2nativepad(BN_n, rsa_n_mem, rsa_n_size) < 0)
	{
		_DIODE_DEBUG_PRINT("Didn't copy the correct size of bytes from the n paramter BIGNUM to binary buffer!\n");
		BN_clear_free(BN_n); BN_clear_free(BN_e); BN_clear_free(BN_d);
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem);
		return -13;
	}
	BN_clear_free(BN_n);

	if(BN_bn2nativepad(BN_e, rsa_e_mem, rsa_e_size) < 0)
	{
		_DIODE_DEBUG_PRINT("Didn't copy the correct size of bytes from the e paramter BIGNUM to binary buffer!\n");
		BN_clear_free(BN_e); BN_clear_free(BN_d);
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem);
		return -13;
	}
	BN_clear_free(BN_e);

	if(BN_bn2nativepad(BN_d, rsa_d_mem, rsa_d_size) < 0)
	{
		_DIODE_DEBUG_PRINT("Didn't copy the correct size of bytes from the d paramter BIGNUM to binary buffer!\n");
		BN_clear_free(BN_d);
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem);
		return -13;
	}
	BN_clear_free(BN_d);


	/* Setting up for b64 conversion */

	uint_fast32_t free_rsa_n_chars = 0;
	uint_fast32_t free_rsa_e_chars = 0;
	uint_fast32_t free_rsa_d_chars = 0;

	if(!rsa_n_chars)
	{
		rsa_n_chars = malloc(sizeof(*rsa_n_chars));
		if(!rsa_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for rsa_n_chars!\n");
			free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem);
			return -14;
		}
		free_rsa_n_chars = 1;
	}

	if(!rsa_e_chars)
	{
		rsa_e_chars = malloc(sizeof(*rsa_e_chars));
		if(!rsa_e_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for rsa_e_chars!\n");
			free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem);
			if(free_rsa_n_chars)
				free(rsa_n_chars);
			return -14;
		}
		free_rsa_e_chars = 1;
	}

	if(!rsa_d_chars)
	{
		rsa_d_chars = malloc(sizeof(*rsa_d_chars));
		if(!rsa_d_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for rsa_d_chars!\n");
			free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem);
			if(free_rsa_n_chars)
				free(rsa_n_chars);
			if(free_rsa_e_chars)
				free(rsa_e_chars);
			return -14;
		}
		free_rsa_d_chars = 1;
	}

	*rsa_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(rsa_n_size);
	*rsa_e_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(rsa_e_size);
	*rsa_d_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(rsa_d_size);

	/* Now let's allocate strings memory and do conversion */

	*rsa_n_str = malloc(*rsa_n_chars + 1);
	if(!(*rsa_n_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for n parameter string!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem);
		if(free_rsa_n_chars)
			free(rsa_n_chars);
		if(free_rsa_e_chars)
			free(rsa_e_chars);
		if(free_rsa_d_chars)
			free(rsa_d_chars);
		return -15;
	}
	if(free_rsa_n_chars)
		free(rsa_n_chars);

	if(_diode_BinaryToBase64Str(rsa_n_mem, rsa_n_size, *rsa_n_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert n parameter binary to base64!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem);
		if(free_rsa_e_chars)
			free(rsa_e_chars);
		if(free_rsa_d_chars)
			free(rsa_d_chars);
		free(*rsa_n_str);
		return -16;
	}
	free(rsa_n_mem);


	*rsa_e_str = malloc(*rsa_e_chars + 1);
	if(!(*rsa_e_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for e parameter string!\n");
		free(rsa_e_mem); free(rsa_d_mem);
		if(free_rsa_e_chars)
			free(rsa_e_chars);
		if(free_rsa_d_chars)
			free(rsa_d_chars);
		free(*rsa_n_str);
		return -17;
	}
	if(free_rsa_e_chars)
		free(rsa_e_chars);

	if(_diode_BinaryToBase64Str(rsa_e_mem, rsa_e_size, *rsa_e_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert e parameter binary to base64!\n");
		free(rsa_e_mem); free(rsa_d_mem);
		if(free_rsa_d_chars)
			free(rsa_d_chars);
		free(*rsa_n_str); free(*rsa_e_str);
		return -18;
	}
	free(rsa_e_mem);


	*rsa_d_str = malloc(*rsa_d_chars + 1);
	if(!(*rsa_d_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for d parameter string!\n");
		free(rsa_d_mem);
		if(free_rsa_d_chars)
			free(rsa_d_chars);
		free(*rsa_n_str); free(*rsa_e_str);
		return -19;
	}
	if(free_rsa_d_chars)
		free(rsa_d_chars);

	if(_diode_BinaryToBase64Str(rsa_d_mem, rsa_d_size, *rsa_d_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert d parameter binary to base64!\n");
		free(rsa_d_mem);
		free(*rsa_n_str); free(*rsa_e_str); free(*rsa_d_str);
		return -20;
	}
	free(rsa_d_mem);

	return 0;
}


/* This function Generates a random pair of ED25519 Keys.
 * *pub_key_str will hold the public key in b64 format and *prv_key_str will hold the private key in b64 format.
 * These strings will be NULL terminated, but if you wish you can provide pub_n_chars and prv_n_chars,
 * where the size of the public key in b64 chars will be written to *pub_n_chars and the same for the private key to *prv_n_chars.
 * If you don't wish to know the sizes, NULL can be given to pub_n_chars and/or prv_n_chars.
 *
 * Error Codes:
 * -1  A NULL pointer was given for pub_key_str or prv_key_str.
 * -2  Couldn't create EVP_PKEY object, ED25519 keys couldn't be generated.
 * -3  Couldn't get private key size.
 * -4  Couldn't get public key size.
 * -5  Couldn't allocate memory for the private key.
 * -6  Couldn't allocate memory for the public key.
 * -7  Couldn't get Private key binary.
 * -8  Couldn't get Public key binary.
 * -9  Couldn't allocate memory for pub_n_chars.
 * -10 Couldn't allocate memory for prv_n_chars.
 * -11 Couldn't allocate memory for private key string.
 * -12 Couldn't allocate memory for public key string.
 * -13 Couldn't convert public key binary to base64.
 * -14 Couldn't convert private key binary to base64.
 */
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_ED25519_Keygen(uint_least8_t** OUT pub_key_str, uint_least32_t* OUT pub_n_chars,
		uint_least8_t** OUT prv_key_str, uint_least32_t* OUT prv_n_chars)
{
	if((!pub_key_str) | (!prv_key_str))
	{
		_DIODE_DEBUG_PRINT("A NULL pointer was given for pub_key_str or prv_key_str!\n");
		return -1;
	}

	EVP_PKEY* keys = EVP_PKEY_Q_keygen(NULL,NULL,"ED25519");

	if(!keys)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_PKEY object, ED25519 keys couldn't be generated!\n");
		return -2;
	}

	/* EVP_PKEY_print_private_fp(stdout, keys, 0, NULL); */

	size_t prv_size;
	size_t pub_size;

	/* Getting lenght sizes */
	if(!EVP_PKEY_get_raw_private_key(keys, NULL, &prv_size))
	{
		_DIODE_DEBUG_PRINT("Couldn't get private key size!\n");
		EVP_PKEY_free(keys);
		return -3;
	}
	if(!EVP_PKEY_get_raw_public_key(keys, NULL, &pub_size))
	{
		_DIODE_DEBUG_PRINT("Couldn't get public key size!\n");
		EVP_PKEY_free(keys);
		return -4;
	}
	
	uint_least8_t* prv_key = malloc(prv_size);
	if(!prv_key)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for the private key!\n");
		EVP_PKEY_free(keys);
		return -5;
	}

	uint_least8_t* pub_key = malloc(pub_size);
	if(!pub_key)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for the public key!\n");
		free(prv_key);
		EVP_PKEY_free(keys);
		return -6;
	}

	/* Writing binary of keys */
	if(!EVP_PKEY_get_raw_private_key(keys, prv_key, &prv_size))
	{
		_DIODE_DEBUG_PRINT("Couldn't get Private key binary!\n");
		free(prv_key);
		free(pub_key);
		EVP_PKEY_free(keys);
		return -7;
	}

        if(!EVP_PKEY_get_raw_public_key(keys, pub_key, &pub_size))
	{
		_DIODE_DEBUG_PRINT("Couldn't get Public key binary!\n");
		free(prv_key);
		free(pub_key);
		EVP_PKEY_free(keys);
		return -8;
	}

	/* Setting up for b64 conversion */

	uint_fast32_t free_pub_n_chars = 0;
	uint_fast32_t free_prv_n_chars = 0;

	if(!pub_n_chars)
	{
		pub_n_chars = malloc(sizeof(*pub_n_chars));
		if(!pub_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for pub_n_chars!\n");
			free(prv_key);
			free(pub_key);
			EVP_PKEY_free(keys);
			return -9;
		}
		free_pub_n_chars = 1;
	}

	if(!prv_n_chars)
	{
		prv_n_chars = malloc(sizeof(*prv_n_chars));
		if(!pub_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for prv_n_chars!\n");
			free(prv_key);
			free(pub_key);
			EVP_PKEY_free(keys);
			if(free_pub_n_chars)
				free(pub_n_chars);
			return -10;
		}
		free_prv_n_chars = 1;
	}

	*pub_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(pub_size);
	*prv_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(prv_size);

	*prv_key_str = malloc(*prv_n_chars + 1);
	if(!(*prv_key_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for private key string!\n");
		free(prv_key);
		free(pub_key);
		EVP_PKEY_free(keys);
		if(!free_pub_n_chars)
			free(pub_n_chars);
		if(!free_prv_n_chars)
			free(prv_n_chars);
		return -11;
	}

	*pub_key_str = malloc(*pub_n_chars + 1);
	if(!(*pub_key_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for public key string!\n");
		free(prv_key);
		free(pub_key);
		EVP_PKEY_free(keys);
		if(!free_pub_n_chars)
			free(pub_n_chars);
		if(!free_prv_n_chars)
			free(prv_n_chars);
		free(*prv_key_str);
		return -12;
	}

	/* Key to b64 conversion */
	
	if(_diode_BinaryToBase64Str(pub_key, pub_size, *pub_key_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert public key binary to base64!\n");
		free(prv_key);
		free(pub_key);
		EVP_PKEY_free(keys);
		if(!free_pub_n_chars)
			free(pub_n_chars);
		if(!free_prv_n_chars)
			free(prv_n_chars);
		free(*prv_key_str);
		free(*pub_key_str);
		return -13;
	}

	if(_diode_BinaryToBase64Str(prv_key, prv_size, *prv_key_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert private key binary to base64!\n");
		free(prv_key);
		free(pub_key);
		EVP_PKEY_free(keys);
		if(!free_pub_n_chars)
			free(pub_n_chars);
		if(!free_prv_n_chars)
			free(prv_n_chars);
		free(*prv_key_str);
		free(*pub_key_str);
		return -14;
	}

	if(!free_pub_n_chars)
		free(pub_n_chars);
	if(!free_prv_n_chars)
		free(prv_n_chars);
	free(prv_key);
	free(pub_key);
	EVP_PKEY_free(keys);
	return 0;
}


/* Generates a signature from a given string of a private key in base64 chars and a message,
 * Takes in the string (msg) to make the signature , private key string (b64_key),
 * and allocates a string pointer, to be returned by the function, with the signature.
 * If the msg_len is given to be 0, then msg is expected to be null terminated to find the size.
 * key bits lenght MUST be divisable by 8.
 *
 * free() must be called to free the returned string memory by the caller.
 * If the singning failed NULL is returned.
 */
uint_least8_t* EMSCRIPTEN_KEEPALIVE _diode_SignString_wED25519PrivateBase64Key(const unsigned char* const IN msg, size_t msg_len,
		const unsigned char* const IN b64_key)
{
	if((!msg) | (!b64_key))
	{
		_DIODE_DEBUG_PRINT("A NULL pointer was given as the msg or b64_key!\n");
		return NULL;
	}

	uint_least8_t* OUT sig_str = NULL;
	uint_least8_t* mem;

	EVP_PKEY* prv_key = NULL;

	/* Base64 key string to binary conversion */
	int_fast32_t n_bytes = _diode_AmountOfBytesFromB64Str(b64_key, 0);
	if(n_bytes == -1)
	{
		_DIODE_DEBUG_PRINT("Invalid b64 key given!!!\n");
		return NULL;
	}

	mem = malloc(n_bytes);
	if(!mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate key memory!\n");
		return NULL;
	}

	if(_diode_Base64StrToBinary(b64_key, mem, 0))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert b64 key to binary!\n");
		free(mem);
		return NULL;
	}

	/* creating Key and CTX objects */
	prv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, mem, n_bytes);
	if(!prv_key)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_PKEY object!\n");
		free(mem);
		return NULL;
	}

	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_MD_CTX object!\n");
		free(mem);
		EVP_PKEY_free(prv_key);
		return NULL;
	}


	/* Initialization for signing */
	if(!msg_len)
		msg_len = strlen((char*)msg);
	if(!EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, prv_key))
	{
		_DIODE_DEBUG_PRINT("Couldn't Initialize CTX!\n");
		free(mem);
		EVP_PKEY_free(prv_key);
		EVP_MD_CTX_free(md_ctx);
		return NULL;
	}

	/* Calculate the required size for the signature by passing a NULL */
	size_t sig_len = 0;
	if(!EVP_DigestSign(md_ctx, NULL, &sig_len, msg, msg_len))
	{
		_DIODE_DEBUG_PRINT("Couldn't get signature size!\n");
		free(mem);
		EVP_PKEY_free(prv_key);
		EVP_MD_CTX_free(md_ctx);
		return NULL;
	}

	free(mem);
	mem = OPENSSL_zalloc(sig_len);	
	if(!mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate signature memory!\n");
		EVP_PKEY_free(prv_key);
		EVP_MD_CTX_free(md_ctx);
		return NULL;
	}

	/* Signing */
	if(!EVP_DigestSign(md_ctx, mem, &sig_len, msg, msg_len))
	{
		_DIODE_DEBUG_PRINT("Couldn't Sign!\n");
		EVP_PKEY_free(prv_key);
		EVP_MD_CTX_free(md_ctx);
		OPENSSL_free(mem);
		return NULL;
	}

	sig_str = malloc(_DIODE_BASE64STR_SIZE_FROM_NBYTES(sig_len) + 1);
	if(!sig_str)
	{
		_DIODE_DEBUG_PRINT("Couldn't Sign!\n");
		EVP_PKEY_free(prv_key);
		EVP_MD_CTX_free(md_ctx);
		OPENSSL_free(mem);
		return NULL;
	}

	/* signature to b64 conversion */
	if(_diode_BinaryToBase64Str(mem, sig_len, sig_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert signature binary to b64 string!\n");
		EVP_PKEY_free(prv_key);
		EVP_MD_CTX_free(md_ctx);
		OPENSSL_free(mem);
		return NULL;
	}

	EVP_PKEY_free(prv_key);
	EVP_MD_CTX_free(md_ctx);
	OPENSSL_free(mem);
	return sig_str;
}


/* The functions verifies the given base64 encoded signature (sig) against the given message (msg) with the base64 encoded (public) key (b64_key).
 * All strings must be null terminated.
 * returns 1 on success, 0 on failure, negative value for an error
 *
 * Error Codes:
 * -1  Either sig, b64_key or msg was given as a NULL pointer.
 * -2  Couldn't get size of memory for b64 key.
 * -3  Couldn't allocate memory for key.
 * -4  Couldn't convert b64 key to binary.
 * -5  Couldn't get size of memory for signature.
 * -6  Couldn't allocate memory for signature.
 * -7  Couldn't convert signature to binary.
 * -8  Couldn't create EVP_PKEY object.
 * -9  Couldn't create EVP_MD_CTX object.
 * -10 Couldn't Initialize context for signing.
 * -11 Couldn't perform the verifiction.
 */
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_VerifySig_wED25519PublicBase64Key(const unsigned char* const IN sig, const unsigned char* const IN b64_key,
		const unsigned char* const IN msg)
{
	if((!sig) | (!b64_key) | (!msg))
	{
		_DIODE_DEBUG_PRINT("A NULL pointer was given!\n");
		return -1;
	}

	int_fast8_t success = 0; /* 0 is for failure */
	uint_least8_t* key_mem;
	uint_least8_t* sig_mem;
	EVP_PKEY* pub_key;

	/* Base64 key string to binary conversion */
	int_fast32_t key_n_bytes = _diode_AmountOfBytesFromB64Str(b64_key,0);
	if(key_n_bytes < 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't get size of memory for b64 key!\n");
		return -2;
	}

	key_mem = malloc(key_n_bytes);
	if(!key_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for key!\n");
		return -3;
	}

	if(_diode_Base64StrToBinary(b64_key, key_mem, 0))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert b64 key to binary!\n");
		free(key_mem);
		return -4;
	}

	/* Base64 signature to binary conversion */	
	int_fast32_t sig_n_bytes = _diode_AmountOfBytesFromB64Str(sig,0);
	if(sig_n_bytes < 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't get size of memory for signature!\n");
		free(key_mem);
		return -5;
	}

	sig_mem = malloc(sig_n_bytes);
	if(!sig_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for signature!\n");
		free(key_mem);
		return -6;
	}

	if(_diode_Base64StrToBinary(sig, sig_mem, 0))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert signature to binary!\n");
		free(key_mem);
		free(sig_mem);
		return -7;
	}

	/* Public Key Creation */
	pub_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key_mem, key_n_bytes);
	if(!pub_key)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_PKEY object!\n");
		free(key_mem);
		free(sig_mem);
		return -8;
	}

	/* printf("VERIFY KEY:\n");
	EVP_PKEY_print_public_fp(stdout, pub_key, 0, NULL); */

	/* Verification */
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
	if(!md_ctx)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_MD_CTX object!\n");
		free(key_mem);
		free(sig_mem);
		EVP_PKEY_free(pub_key);
		return -9;
	}

	if(!EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pub_key))
	{
		_DIODE_DEBUG_PRINT("Couldn't Initialize context for signing!\n");
		free(key_mem);
		free(sig_mem);
		EVP_PKEY_free(pub_key);
		EVP_MD_CTX_free(md_ctx);
		return -10;
	}

	success = EVP_DigestVerify(md_ctx, sig_mem, sig_n_bytes, msg, strlen((char*)msg));
	if((success > 1) | (success < 0))
	{	
		_DIODE_DEBUG_PRINT("Couldn't perform the verifiction!!!! Openssl ERR: %lu\n", ERR_peek_error());
		success = -11;
	}

	/* Cleanup */
	free(key_mem);
	free(sig_mem);
	EVP_PKEY_free(pub_key);
	EVP_MD_CTX_free(md_ctx);

	return success;
}

#ifndef MCELIECE460896F_PUBLICKEYBYTES
#define MCELIECE460896F_PUBLICKEYBYTES 524160
#endif

#ifndef MCELIECE460896F_SECRETKEYBYTES
#define MCELIECE460896F_SECRETKEYBYTES 13608
#endif

/*
#define crypto_kem_mceliece460896f_ref_CIPHERTEXTBYTES 156
#define crypto_kem_mceliece460896f_ref_BYTES 32
*/

int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_mceliece460896f_Keygen(uint_least8_t** OUT pub_key_str, uint_least32_t* OUT pub_n_chars,
                uint_least8_t** OUT prv_key_str, uint_least32_t* OUT prv_n_chars)
{
	if((!pub_key_str) | (!prv_key_str))
	{
		_DIODE_DEBUG_PRINT("A NULL pointer was provided for one of the strings!\n");
		return -1;
	}

	/* Allocate memory for keys */
	uint_least8_t* prv_key = malloc(MCELIECE460896F_SECRETKEYBYTES);
	if (!prv_key)
	{
		_DIODE_DEBUG_PRINT("Couldn't Allocate memory for McEliece's Private key!\n");
		return -2;
	}

	uint_least8_t* pub_key = malloc(MCELIECE460896F_PUBLICKEYBYTES);
	if (!pub_key)
	{
		_DIODE_DEBUG_PRINT("Couldn't Allocate memory McEliece Public key!\n");
		free(prv_key);
		return -3;
	}

	/* Generate keys */
	if(crypto_kem_mceliece460896f_ref_keypair(pub_key, prv_key))
	{
		_DIODE_DEBUG_PRINT("Couldn't generate McEliece key pair!!\n");
		free(prv_key);
		free(pub_key);
		return -4;
	}

	/* Allocate memory for b64 strings of keys */
	uint_fast8_t free_prv_n_chars = 0;
	uint_fast8_t free_pub_n_chars = 0;

	if(!prv_n_chars)
	{
		prv_n_chars = malloc(sizeof(*prv_n_chars));
		if(!prv_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for prv_n_chars!\n");
			free(prv_key);
			free(pub_key);
			return -5;
		}
		free_prv_n_chars = 1;
	}

	if(!pub_n_chars)
	{
		pub_n_chars = malloc(sizeof(*pub_n_chars));
		if(!pub_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for pub_n_chars!\n");
			free(prv_key);
			free(pub_key);
			if(free_prv_n_chars)
				free(prv_n_chars);
			return -6;
		}
		free_pub_n_chars = 1;
	}

	*prv_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(MCELIECE460896F_SECRETKEYBYTES);
	*pub_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(MCELIECE460896F_PUBLICKEYBYTES);

	*prv_key_str = malloc(*prv_n_chars + 1);
	if(!(*prv_key_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for private key string!\n");
		free(prv_key);
		free(pub_key);
		if(free_prv_n_chars)
			free(prv_n_chars);
		if(free_pub_n_chars)
			free(pub_n_chars);
		return -7;
	}

	*pub_key_str = malloc(*pub_n_chars + 1);
	if(!(*pub_key_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for public key string!\n");
		free(prv_key);
		free(pub_key);
		if(free_prv_n_chars)
			free(prv_n_chars);
		if(free_pub_n_chars)
			free(pub_n_chars);
		free(*prv_key_str);
		return -8;
	}

	/* Convert key binaries to b64 strings */
	if(_diode_BinaryToBase64Str(prv_key, MCELIECE460896F_SECRETKEYBYTES, *prv_key_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert private key to b64!\n");
		free(prv_key);
		free(pub_key);
		if(free_prv_n_chars)
			free(prv_n_chars);
		if(free_pub_n_chars)
			free(pub_n_chars);
		free(*prv_key_str);
		free(*pub_key_str);
		return -9;
	}
	free(prv_key);

	if(_diode_BinaryToBase64Str(pub_key, MCELIECE460896F_PUBLICKEYBYTES, *pub_key_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert public key to b64!\n");
		if(free_prv_n_chars)
			free(prv_n_chars);
		if(free_pub_n_chars)
			free(pub_n_chars);
		free(*prv_key_str);
		free(*pub_key_str);
		free(pub_key);
		return -10;
	}
	free(pub_key);
	
	if(free_prv_n_chars)
		free(prv_n_chars);
	if(free_pub_n_chars)
		free(pub_n_chars);

	return 0;
}


/* This function generates a secret and an encapsulated out with the provided RSA n and e parameter strings in b64 format.
 * The parameter string sizes in b64 chars can be provided, if a string is null terminated the size can be given as 0.
 * Both the secret_str and out_str will be in b64 format, their sizes in chars will be written to *out_n_chars and *secret_n_chars,
 * altough these strings will be null terminated, so if you wish you may make out_n_chars and secret_n_chars NULL.
 *
 * Error Codes:
 * -1  A NULL pointer was provided to out_str, secret_str, rsa_n_str or rsa_e_str.
 * -2  Couldn't get size of memory for e or n parameters.
 * -3  Couldn't allocate memory for rsa n or e parameter.
 * -4  Couldn't convert b64 parameter n or e string to binary.
 * -5  Couldn't create EVP_PKEY_CTX object for RSA parameters.
 * -6  Couldn't initialize EVP_PKEY_CTX object for RSA parameters.
 * -7  Couldn't create parameter EVP_PKEY.
 * -8  CTX creation for encapsulation from key failed.
 * -9  Couldn't initialize for encapsulation.
 * -10 Couldn't set kem operation as RSAVE.
 * -11 Couldn't get memory sizes for encapsulation.
 * -12 Couldn't allocate memory for out.
 * -13 Couldn't allocate memory for secret.
 * -14 Couldn't encapsulate.
 * -15 Couldn't allocate memory for out_n_chars.
 * -16 Couldn't allocate memory for secret_n_chars.
 * -17 Couldn't allocate memory for out string.
 * -18 Couldn't allocate memory for secret string.
 */
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_encapsulate(unsigned char* IN rsa_n_str, uint_least32_t rsa_n_chars,
		unsigned char* IN rsa_e_str, uint_least32_t rsa_e_chars,
		uint_least8_t** OUT out_str, uint_least32_t* OUT out_n_chars,
		uint_least8_t** OUT secret_str, uint_least32_t* OUT secret_n_chars)
{
	if((!out_str) | (!secret_str) | (!rsa_n_str) | (!rsa_e_str))
	{
		_DIODE_DEBUG_PRINT("A NULL pointer was provided to out_str, secret_str, rsa_n_str or rsa_e_str!\n");
		return -1;
	}

	if(!rsa_n_chars)
		rsa_n_chars = strlen((char*)rsa_n_str);
	if(!rsa_e_chars)
		rsa_e_chars = strlen((char*)rsa_e_str);


	/* Base64 parameter strings to binary conversion */
	int_fast32_t rsa_n_bytes = _diode_AmountOfBytesFromB64Str(rsa_n_str,rsa_n_chars);
	int_fast32_t rsa_e_bytes = _diode_AmountOfBytesFromB64Str(rsa_n_str,rsa_e_chars);
	
	if((rsa_n_bytes < 0) | (rsa_e_bytes < 0))
	{
		_DIODE_DEBUG_PRINT("Couldn't get size of memory for e or n parameters!\n");
		return -2;
	}

	uint_least8_t* rsa_n_mem = malloc(rsa_n_bytes);
	if(!rsa_n_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for rsa n parameter!\n");
		return -3;
	}
	uint_least8_t* rsa_e_mem = malloc(rsa_e_bytes);
	if(!rsa_e_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for rsa e parameter!\n");
		free(rsa_n_mem);
		return -3;
	}

	if(_diode_Base64StrToBinary(rsa_n_str, rsa_n_mem, 0))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert b64 parameter n string to binary!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		return -4;
	}
	if(_diode_Base64StrToBinary(rsa_e_str, rsa_e_mem, 0))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert b64 parameter e string to binary!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		return -4;
	}

	/* Now creating RSA EVP_PKEY object with parameters */	
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if(!pctx)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_PKEY_CTX object for RSA parameters!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		return -5;
	}
	if(!EVP_PKEY_fromdata_init(pctx))
	{
		_DIODE_DEBUG_PRINT("Couldn't initialize EVP_PKEY_CTX object for RSA parameters!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		return -6;
		
	}

	OSSL_PARAM params[3];
	params[0] = OSSL_PARAM_construct_BN("n", rsa_n_mem, rsa_n_bytes);
	params[1] = OSSL_PARAM_construct_BN("e", rsa_e_mem, rsa_e_bytes);
	params[2] = OSSL_PARAM_construct_end();

	EVP_PKEY* param_key;
	if(!EVP_PKEY_fromdata(pctx, &param_key, EVP_PKEY_PUBLIC_KEY, params))
	{
		_DIODE_DEBUG_PRINT("Couldn't create parameter EVP_PKEY!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		EVP_PKEY_CTX_free(pctx);
		return -7;
	}
	/* EVP_PKEY_print_public_fp(stdout, param_key, 2, NULL); */
	
	/* Now let's try encapsulation */

	/* Initialize for encapsulation */
	EVP_PKEY_CTX* ectx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
	if(!ectx)
	{
		_DIODE_DEBUG_PRINT("CTX creation for encapsulation from key failed!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		return -8;
	}
	if (EVP_PKEY_encapsulate_init(ectx, NULL) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't initialize for encapsulation!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_CTX_free(ectx);
		return -9;
	}

	/* Set RSAVE op, only supported for now */
	if (EVP_PKEY_CTX_set_kem_op(ectx, "RSASVE") <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't set kem operation as RSAVE!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_CTX_free(ectx);
		return -10;
	}

	size_t out_size;
	size_t secret_size;

	/* get out and secret memory sizes */
	if (EVP_PKEY_encapsulate(ectx, NULL, &out_size, NULL, &secret_size) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't get memory sizes for encapsulation!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_CTX_free(ectx);
		return -11;
	}

	uint_least8_t* out = malloc(out_size);
	if(!out)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for out!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_CTX_free(ectx);
		return -12;
	}

	uint_least8_t* secret = malloc(secret_size);
	if(!secret)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for secret!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_CTX_free(ectx);
		free(out);
		return -13;
	}

	/* Encapsulate, get out for secret retrievel, and the actual secret secret */
	if(EVP_PKEY_encapsulate(ectx, out, &out_size, secret, &secret_size) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't encapsulate!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_CTX_free(ectx);
		free(out);
		free(secret);
		return -14;
	}


	/* Now out and secret conversion to base64 format */
	uint_fast8_t free_out_n_chars = 0;
	uint_fast8_t free_secret_n_chars = 0;

	if(!out_n_chars)
	{
		out_n_chars = malloc(sizeof(*out_n_chars));
		if(!out_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for out_n_chars!\n");
			free(rsa_n_mem); free(rsa_e_mem);
			EVP_PKEY_free(param_key);
			EVP_PKEY_CTX_free(pctx);
			EVP_PKEY_CTX_free(ectx);
			free(out);
			free(secret);
			return -15;
		}
		free_out_n_chars = 1;
	}

	*out_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(out_size);
	
	if(!secret_n_chars)
	{
		secret_n_chars = malloc(sizeof(*secret_n_chars));
		if(!secret_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for secret_n_chars!\n");
			free(rsa_n_mem); free(rsa_e_mem);
			EVP_PKEY_free(param_key);
			EVP_PKEY_CTX_free(pctx);
			EVP_PKEY_CTX_free(ectx);
			free(out);
			free(secret);
			if(free_out_n_chars)
				free(out_n_chars);
			return -16;
		}
		free_secret_n_chars = 1;
	}

	*secret_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(secret_size);

	*out_str = malloc(*out_n_chars + 1);
	if(!(*out_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for out string!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_CTX_free(ectx);
		free(out);
		free(secret);
		if(free_out_n_chars)
			free(out_n_chars);
		if(free_secret_n_chars)
			free(secret_n_chars);
		return -17;

	}

	*secret_str = malloc(*secret_n_chars + 1);
	if(!(*secret_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for secret string!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_CTX_free(ectx);
		free(out);
		free(secret);
		free(*out_str);
		if(free_out_n_chars)
			free(out_n_chars);
		if(free_secret_n_chars)
			free(secret_n_chars);
		free(*out_str);
		return -18;

	}

	/* Convert out and secret to base64 representations */
	_diode_BinaryToBase64Str(out, out_size, *out_str);
	_diode_BinaryToBase64Str(secret, secret_size, *secret_str);
	
	if(free_out_n_chars)
		free(out_n_chars);
	if(free_secret_n_chars)
		free(secret_n_chars);
	
	free(rsa_n_mem); free(rsa_e_mem);
	EVP_PKEY_free(param_key);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_CTX_free(ectx);
	free(out);
	free(secret);
	return 0;
}
