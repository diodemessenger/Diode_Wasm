#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <_diode_Main.h>
#include <_diode_Utils.h>

#include <_diode_Encryption.h>
#include <operations.h>

#include <openssl/ssl.h>

/* This function encrypts the given data in b64 format with the given RSA public parameters in b64 format, writing the output to *out_str in b64.
 * None of the strings given and out_str can be NULL.
 * rsa_n_chars, rsa_e_chars, data_n_chars can be given in case the strings aren't null terminated, otherwise, these can be given as 0.
 * *out_n_chars will hold the amount of characters written to *out_str, altough this string will be null terminated.
 * If you don't need the char count for out, out_n_chars can be given as NULL.
 *
 * Error Codes:
 * -1  rsa_n_str, rsa_e_str, data_str or out_str are NULL.
 * -2  Couldn't get size of one of the parameters or data binary buffers.
 * -3  Couldn't allocate memory for one of the parameters or data buffers.
 * -4  Couldn't convert one of the b64 strings to binary.
 * -5  Couldn't create EVP_PKEY_CTX object for RSA parameters.
 * -6  Couldn't initialize EVP_PKEY_CTX object for RSA parameters.
 * -7  Couldn't create parameters EVP_PKEY.
 * -8  CTX creation for encryption from key failed.
 * -9  Couldn't initialize for encryption.
 * -10 Coulnd't get out buffer size.
 * -11 Coulnd't allocate memory for out buffer.
 * -12 Coulnd't encrypt.
 * -13 Couldn't allocate memory for out_n_chars.
 * -14 Couldn't allocate memory for out string.
 * -15 Couldn't convert encrypted out to b64 string.
 */
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_encrypt_wB64(unsigned char* IN rsa_n_str, uint_least32_t rsa_n_chars,
		unsigned char* IN rsa_e_str, uint_least32_t rsa_e_chars,
		uint_least8_t* IN data_str, uint_least32_t data_n_chars,
		uint_least8_t** OUT out_str, uint_least32_t* out_n_chars)
{
	if((!rsa_n_str) | (!rsa_e_str) | (!data_str) | (!out_str))
	{
		_DIODE_DEBUG_PRINT("rsa_n_str, rsa_e_str, data_str or out_str are NULL!\n");
		return -1;
	}

	if(!rsa_n_chars)
		rsa_n_chars = strlen((char*)rsa_n_str);
	if(!rsa_e_chars)
		rsa_e_chars = strlen((char*)rsa_e_str);
	if(!data_n_chars)
		data_n_chars = strlen((char*)data_str);

	int_fast32_t rsa_n_bytes = _diode_AmountOfBytesFromB64Str(rsa_n_str,rsa_n_chars);
	int_fast32_t rsa_e_bytes = _diode_AmountOfBytesFromB64Str(rsa_e_str,rsa_e_chars);
	int_fast32_t data_bytes = _diode_AmountOfBytesFromB64Str(data_str,data_n_chars);

	if((rsa_n_bytes < 0) | (rsa_e_bytes < 0) | (data_bytes < 0))
	{
		_DIODE_DEBUG_PRINT("Couldn't get size of one of the parameters or data binary buffers!\n");
		return -2;
	}

	uint_least8_t* rsa_n_mem = malloc(rsa_n_bytes);
	if(!rsa_n_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for n parameter buffer!\n");
		return -3;
	}
	uint_least8_t* rsa_e_mem = malloc(rsa_e_bytes);
	if(!rsa_e_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for e parameter buffer!\n");
		free(rsa_n_mem);
		return -3;
	}
	uint_least8_t* data_mem = malloc(data_bytes);
	if(!data_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for the data buffer!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		return -3;
	}
	
	uint_fast8_t err_hold = _diode_Base64StrToBinary(rsa_n_str, rsa_n_mem, rsa_n_chars);
	err_hold += _diode_Base64StrToBinary(rsa_e_str, rsa_e_mem, rsa_e_chars);
	err_hold += _diode_Base64StrToBinary(data_str, data_mem, data_n_chars);
	
	if(err_hold)
	{
		_DIODE_DEBUG_PRINT("Couldn't convert one of the b64 strings to binary!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
		return -4;
	}

	/* Now creating RSA EVP_PKEY object with parameters */
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if(!pctx)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_PKEY_CTX object for RSA parameters!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
		return -5;
	}

	if(!EVP_PKEY_fromdata_init(pctx))
	{
		_DIODE_DEBUG_PRINT("Couldn't initialize EVP_PKEY_CTX object for RSA parameters!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
		EVP_PKEY_CTX_free(pctx);
		return -6;
        }

	OSSL_PARAM params[3];
	params[0] = OSSL_PARAM_construct_BN("n", rsa_n_mem, rsa_n_bytes);
	params[1] = OSSL_PARAM_construct_BN("e", rsa_e_mem, rsa_e_bytes);
	params[2] = OSSL_PARAM_construct_end();
	
	EVP_PKEY* param_key;
	if(!EVP_PKEY_fromdata(pctx, &param_key, EVP_PKEY_PUBLIC_KEY, params))
	{
		_DIODE_DEBUG_PRINT("Couldn't create parameters EVP_PKEY!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
		EVP_PKEY_CTX_free(pctx);
		return -7;
	}
	/* EVP_PKEY_print_public_fp(stdout, param_key, 2, NULL); */

	/* Now Setting up for encryption */

	/* the EVP_PKEY and parameter EVP_PKEY_CTX contents will not copy to this new EVP_PKEY_CTX, so they can't be deleted */
	EVP_PKEY_CTX* ectx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
	if(!ectx)
	{
		_DIODE_DEBUG_PRINT("CTX creation for encryption from key failed!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		return -8;
	}
	if(EVP_PKEY_encrypt_init(ectx) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't initialize for encryption!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(ectx);
		return -9;
	}

	/* Get out buffer size */
	size_t out_bytes;
	if(EVP_PKEY_encrypt(ectx, NULL, &out_bytes, data_mem, data_bytes) <= 0)
	{
		_DIODE_DEBUG_PRINT("Coulnd't get out buffer size!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(ectx);
		return -10;
	}

	uint_least8_t* out_mem = malloc(out_bytes);
	if(!out_mem)
	{
		_DIODE_DEBUG_PRINT("Coulnd't allocate memory for out buffer!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(ectx);
		return -11;
	}

	/* encrypt */
	if(EVP_PKEY_encrypt(ectx, out_mem, &out_bytes, data_mem, data_bytes) <= 0)
	{
		_DIODE_DEBUG_PRINT("Coulnd't encrypt!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(ectx);
		free(out_mem);
		return -12;
	}

	/* Convert out to b64 */

	uint_fast8_t free_out_n_chars = 0;
	if(!out_n_chars)
	{
		out_n_chars = malloc(sizeof(*out_n_chars));
		if(!out_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for out_n_chars!\n");
			free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
			EVP_PKEY_free(param_key);
			EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(ectx);
			free(out_mem);
			return -13;
		}
		free_out_n_chars = 1;
	}

	*out_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(out_bytes);

	*out_str = malloc(*out_n_chars + 1);
	if(!(*out_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for out string!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(ectx);
		free(out_mem);
		if(free_out_n_chars)
			free(out_n_chars);
		return -14;
	}

	if(_diode_BinaryToBase64Str(out_mem, out_bytes, *out_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert encrypted out to b64 string!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(ectx);
		free(out_mem);
		if(free_out_n_chars)
			free(out_n_chars);
		free(*out_str);
		return -15;
	}


	free(rsa_n_mem); free(rsa_e_mem); free(data_mem);
	EVP_PKEY_free(param_key);
	EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(ectx);
	free(out_mem);
	if(free_out_n_chars)
		free(out_n_chars);
	return 0;
}


/* This function decrypts the given data in b64 format with the given RSA private parameters in b64 format, writing the output to *out_str in b64.
 * None of the strings given and out_str can be NULL.
 * rsa_n_chars, rsa_e_chars, rsa_d_chars and data_n_chars can be given in case the strings aren't null terminated, otherwise, these can be given as 0.
 * *out_n_chars will hold the amount of characters written to *out_str, altough this string will be null terminated.
 * If you don't need the char count for out, out_n_chars can be given as NULL.
 *
 * Error Codes:
 * -1  rsa_n_str, rsa_e_str, rsa_d_str, data_str or out_str are NULL.
 * -2  Couldn't get size of one of the parameters or data binary buffers.
 * -3  Couldn't allocate memory for one of the parameters or data buffers.
 * -4  Couldn't convert one of the b64 strings to binary.
 * -5  Couldn't create EVP_PKEY_CTX object for RSA parameters.
 * -6  Couldn't initialize EVP_PKEY_CTX object for RSA parameters.
 * -7  Couldn't create parameters EVP_PKEY.
 * -8  CTX creation for decryption from key failed.
 * -9  Couldn't initialize for decryption.
 * -10 Coulnd't get out buffer size.
 * -11 Coulnd't allocate memory for out buffer.
 * -12 Coulnd't decrypt.
 * -13 Couldn't allocate memory for out_n_chars.
 * -14 Couldn't allocate memory for out string.
 * -15 Couldn't convert decrypted out to b64 string.
 */
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_decrypt_wB64(unsigned char* IN rsa_n_str, uint_least32_t rsa_n_chars,
		unsigned char* IN rsa_e_str, uint_least32_t rsa_e_chars,
		unsigned char* IN rsa_d_str, uint_least32_t rsa_d_chars,
		uint_least8_t* IN data_str, uint_least32_t data_n_chars,
		uint_least8_t** OUT out_str, uint_least32_t* out_n_chars)
{
	if((!rsa_n_str) | (!rsa_e_str) | (!rsa_d_str) | (!data_str) | (!out_str))
	{
		_DIODE_DEBUG_PRINT("rsa_n_str, rsa_e_str, rsa_d_str, data_str or out_str are NULL!\n");
		return -1;
	}

	if(!rsa_n_chars)
		rsa_n_chars = strlen((char*)rsa_n_str);
	if(!rsa_e_chars)
		rsa_e_chars = strlen((char*)rsa_e_str);
	if(!rsa_d_chars)
		rsa_d_chars = strlen((char*)rsa_d_str);
	if(!data_n_chars)
		data_n_chars = strlen((char*)data_str);

	int_fast32_t rsa_n_bytes = _diode_AmountOfBytesFromB64Str(rsa_n_str,rsa_n_chars);
	int_fast32_t rsa_e_bytes = _diode_AmountOfBytesFromB64Str(rsa_e_str,rsa_e_chars);
	int_fast32_t rsa_d_bytes = _diode_AmountOfBytesFromB64Str(rsa_d_str,rsa_d_chars);
	int_fast32_t data_bytes = _diode_AmountOfBytesFromB64Str(data_str,data_n_chars);

	if((rsa_n_bytes < 0) | (rsa_e_bytes < 0) | (rsa_d_bytes < 0) | (data_bytes < 0))
	{
		_DIODE_DEBUG_PRINT("Couldn't get size of one of the parameters or data binary buffers!\n");
		return -2;
	}

	uint_least8_t* rsa_n_mem = malloc(rsa_n_bytes);
	if(!rsa_n_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for n parameter buffer!\n");
		return -3;
	}
	uint_least8_t* rsa_e_mem = malloc(rsa_e_bytes);
	if(!rsa_e_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for e parameter buffer!\n");
		free(rsa_n_mem);
		return -3;
	}
	uint_least8_t* rsa_d_mem = malloc(rsa_d_bytes);
	if(!rsa_d_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for d parameter buffer!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		return -3;
	}
	uint_least8_t* data_mem = malloc(data_bytes);
	if(!data_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for the data buffer!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem);
		return -3;
	}
	
	uint_fast8_t err_hold = _diode_Base64StrToBinary(rsa_n_str, rsa_n_mem, rsa_n_chars);
	err_hold += _diode_Base64StrToBinary(rsa_e_str, rsa_e_mem, rsa_e_chars);
	err_hold += _diode_Base64StrToBinary(rsa_d_str, rsa_d_mem, rsa_d_chars);
	err_hold += _diode_Base64StrToBinary(data_str, data_mem, data_n_chars);
	
	if(err_hold)
	{
		_DIODE_DEBUG_PRINT("Couldn't convert one of the b64 strings to binary!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		return -4;
	}

	/* Now creating RSA EVP_PKEY object with parameters */
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if(!pctx)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_PKEY_CTX object for RSA parameters!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		return -5;
	}

	if(!EVP_PKEY_fromdata_init(pctx))
	{
		_DIODE_DEBUG_PRINT("Couldn't initialize EVP_PKEY_CTX object for RSA parameters!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_CTX_free(pctx);
		return -6;
        }

	OSSL_PARAM params[4];
	params[0] = OSSL_PARAM_construct_BN("n", rsa_n_mem, rsa_n_bytes);
	params[1] = OSSL_PARAM_construct_BN("e", rsa_e_mem, rsa_e_bytes);
	params[2] = OSSL_PARAM_construct_BN("d", rsa_d_mem, rsa_d_bytes);
	params[3] = OSSL_PARAM_construct_end();
	
	EVP_PKEY* param_key;
	if(!EVP_PKEY_fromdata(pctx, &param_key, EVP_PKEY_KEYPAIR, params))
	{
		_DIODE_DEBUG_PRINT("Couldn't create parameters EVP_PKEY!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_CTX_free(pctx);
		return -7;
	}
	/* EVP_PKEY_print_private_fp(stdout, param_key, 2, NULL); */

	/* Now Setting up for decryption */

	/* the EVP_PKEY and parameter EVP_PKEY_CTX contents will not copy to this new EVP_PKEY_CTX, so they can't be deleted */
	EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
	if(!dctx)
	{
		_DIODE_DEBUG_PRINT("CTX creation for decryption from key failed!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		return -8;
	}
	if(EVP_PKEY_decrypt_init(dctx) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't initialize for decryption!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(dctx);
		return -9;
	}

	/* Get out buffer size */
	size_t out_bytes;
	if(EVP_PKEY_decrypt(dctx, NULL, &out_bytes, data_mem, data_bytes) <= 0)
	{
		_DIODE_DEBUG_PRINT("Coulnd't get out buffer size!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(dctx);
		return -10;
	}

	uint_least8_t* out_mem = malloc(out_bytes);
	if(!out_mem)
	{
		_DIODE_DEBUG_PRINT("Coulnd't allocate memory for out buffer!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(dctx);
		return -11;
	}

	/* decrypt */
	if(EVP_PKEY_decrypt(dctx, out_mem, &out_bytes, data_mem, data_bytes) <= 0)
	{
		_DIODE_DEBUG_PRINT("Coulnd't decrypt!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(dctx);
		free(out_mem);
		return -12;
	}

	/* Convert out to b64 */

	uint_fast8_t free_out_n_chars = 0;
	if(!out_n_chars)
	{
		out_n_chars = malloc(sizeof(*out_n_chars));
		if(!out_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for out_n_chars!\n");
			free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
			EVP_PKEY_free(param_key);
			EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(dctx);
			free(out_mem);
			return -13;
		}
		free_out_n_chars = 1;
	}

	*out_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(out_bytes);

	*out_str = malloc(*out_n_chars + 1);
	if(!(*out_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for out string!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(dctx);
		free(out_mem);
		if(free_out_n_chars)
			free(out_n_chars);
		return -14;
	}

	if(_diode_BinaryToBase64Str(out_mem, out_bytes, *out_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert decrypted out to b64 string!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(dctx);
		free(out_mem);
		if(free_out_n_chars)
			free(out_n_chars);
		free(*out_str);
		return -15;
	}


	free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
	EVP_PKEY_free(param_key);
	EVP_PKEY_CTX_free(pctx); EVP_PKEY_CTX_free(dctx);
	free(out_mem);
	if(free_out_n_chars)
		free(out_n_chars);
	return 0;
}

#define GFBITS 13
#define SYS_N 4608
#define SYS_T 96
#define PK_NROWS (SYS_T*GFBITS) 
#define SYND_BYTES ((PK_NROWS + 7)/8)
extern void encrypt(unsigned char *s, const unsigned char *pk, unsigned char *e);

/* WIP */
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_mceliece460896f_encrypt_wB64(unsigned char* IN pub_key_str, uint_least32_t pub_key_chars,
		uint_least8_t* IN data_str, uint_least32_t data_n_chars,
		uint_least8_t** OUT out_str, uint_least32_t* out_n_chars)
{
	if((!pub_key_str) | (!data_str) | (!out_str))
	{
		_DIODE_DEBUG_PRINT("pub_key_str, data_str or out_str are NULL!\n");
		return -1;
	}

	if(!pub_key_chars)
		pub_key_chars = strlen((char*)pub_key_str);
	if(!data_n_chars)
		data_n_chars = strlen((char*)data_str);

	int_fast32_t pub_key_bytes = _diode_AmountOfBytesFromB64Str(pub_key_str,pub_key_chars);
	int_fast32_t data_bytes = _diode_AmountOfBytesFromB64Str(data_str,data_n_chars);

	if((pub_key_bytes < 0) | (data_bytes < 0))
	{
		_DIODE_DEBUG_PRINT("Couldn't get size of one of the parameters or data binary buffers!\n");
		return -2;
	}

	uint_least8_t* pub_key_mem = malloc(pub_key_bytes);
	if(!pub_key_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for pub_key buffer!\n");
		return -3;
	}
	uint_least8_t* data_mem = malloc(data_bytes);
	if(!data_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for the data buffer!\n");
		free(pub_key_mem);
		return -3;
	}
	
	uint_fast8_t err_hold = _diode_Base64StrToBinary(pub_key_str, pub_key_mem, pub_key_chars);
	err_hold += _diode_Base64StrToBinary(data_str, data_mem, data_n_chars);
	
	if(err_hold)
	{
		_DIODE_DEBUG_PRINT("Couldn't convert one of the b64 strings to binary!\n");
		free(pub_key_mem); free(data_mem);
		return -4;
	}

	/* Now encryption */

	uint_least8_t* out_mem = malloc(SYND_BYTES);
	if(!out_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for out memory!\n");
		free(pub_key_mem); free(data_mem);
		return -5;
	}
	uint_least8_t* error_vec = malloc(SYS_N/8);
	if(!error_vec)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for error vector memory!\n");
		free(pub_key_mem); free(data_mem);
		free(out_mem);
		return -5;
	}

	printf("vec size: %d", SYS_N/8);
	encrypt(out_mem, pub_key_mem, error_vec);

	free(error_vec);

	uint_fast8_t free_out_n_chars = 0;
	if(!out_n_chars)
	{
		out_n_chars = malloc(sizeof(out_n_chars));
		if(!out_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for out_n_chars!\n");
			free(pub_key_mem); free(data_mem);
			free(out_mem);
			return -6;
		}
		free_out_n_chars = 1;
	}

	*out_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(SYND_BYTES);
	*out_str = malloc((*out_n_chars) * sizeof(**out_str) + 1);
	if(*out_str)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for out string!\n");
		free(pub_key_mem); free(data_mem);
		free(out_mem);
		if(free_out_n_chars)
			free(out_n_chars);
		return -7;
	}

	if(_diode_BinaryToBase64Str(out_mem, SYND_BYTES, *out_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert out binary to a b64 string!\n");
		free(pub_key_mem); free(data_mem);
		free(out_mem);
		if(free_out_n_chars)
			free(out_n_chars);
		free(*out_str);
		return -8;
	}

	free(pub_key_mem); free(data_mem);
	free(out_mem);
	if(free_out_n_chars)
		free(out_n_chars);

	return 0;
}
