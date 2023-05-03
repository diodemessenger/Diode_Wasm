#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <_diode_Main.h>
#include <_diode_Utils.h>

#include <_diode_Kem.h>
#include <crypto_kem_mceliece460896f.h>
#include <operations.h>

#include <openssl/ssl.h>

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
 * -19 Couldn't convert out binary to a b64 string.
 * -20 Couldn't convert secret binary to a b64 string.
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
		if(free_out_n_chars)
			free(out_n_chars);
		if(free_secret_n_chars)
			free(secret_n_chars);
		free(*out_str);
		return -18;
	}

	/* Convert out and secret to base64 representations */
	if(_diode_BinaryToBase64Str(out, out_size, *out_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert out binary to a b64 string!\n");
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
		free(*out_str);
		free(*secret_str);
		return -19;

	}
	if(_diode_BinaryToBase64Str(secret, secret_size, *secret_str))
	{	
		_DIODE_DEBUG_PRINT("Couldn't convert secret binary to a b64 string!\n");
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
		free(*out_str);
		free(*secret_str);
		return -20;
	}
	
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


/* This function decapsulates the given out, with the given n,e,d parameters in b64 format, outputing the secret in b64 format.
 * The parameter string sizes in b64 chars can be provided, if a string is null terminated the size can be given as 0.
 * The secret_str will be in b64 format, the size in chars will be written to *secret_n_chars,
 * altough this strings will be null terminated, so if you wish you may make secret_n_chars NULL.
 *
 * Error Codes:
 * -1  A NULL pointer was provided to out_str, rsa_n_str, rsa_e_str, rsa_d_str or secret_str.
 * -2  Couldn't get size of memory for parameters or data binary.
 * -3  Couldn't allocate memory for one of the RSA parameters or data buffers.
 * -4  Couldn't convert one or more b64 strings to binary.
 * -5  Couldn't create EVP_PKEY_CTX object for RSA parameters.
 * -6  Couldn't initialize EVP_PKEY_CTX object for RSA parameters.
 * -7  Couldn't allocate memory for OSSL_PARAM objects.
 * -8  Couldn't create parameters EVP_PKEY.
 * -9  CTX creation for decapsulation from key failed.
 * -10 Couldn't initialize for decapsulation.
 * -11 Couldn't set key context for RSAVE operation.
 * -12 Couldn't get secret max memory size.
 * -13 Couldn't allocate memory for secret.
 * -14 Couldn't decapsulate.
 * -15 Couldn't allocate memory for secret_n_chars.
 * -16 Couldn't allocate memory for data string.
 * -17 Couldn't convert wrapped data to b64 string.
 */
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_decapsulate(unsigned char* IN rsa_n_str, uint_least32_t rsa_n_chars,
		unsigned char* IN rsa_e_str, uint_least32_t rsa_e_chars,
		unsigned char* IN rsa_d_str, uint_least32_t rsa_d_chars,
		uint_least8_t* IN data_str, uint_least32_t data_n_chars,
		uint_least8_t** OUT secret_str, uint_least32_t* OUT secret_n_chars)
{
	if((!rsa_n_str) | (!rsa_e_str) | (!rsa_d_str) | (!data_str) | (!secret_str))
	{
		_DIODE_DEBUG_PRINT("A NULL pointer was given to one of the strings!\n");
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
	
	/* Convert strings to binary */	
	int_fast32_t rsa_n_bytes = _diode_AmountOfBytesFromB64Str(rsa_n_str,rsa_n_chars);
	int_fast32_t rsa_e_bytes = _diode_AmountOfBytesFromB64Str(rsa_e_str,rsa_e_chars);
	int_fast32_t rsa_d_bytes = _diode_AmountOfBytesFromB64Str(rsa_d_str,rsa_d_chars);
	int_fast32_t data_bytes = _diode_AmountOfBytesFromB64Str(data_str,data_n_chars);


	if((rsa_n_bytes < 0) | (rsa_e_bytes < 0) | (rsa_d_bytes < 0) | (data_bytes < 0))
	{
		_DIODE_DEBUG_PRINT("Couldn't get size of memory for parameters or data binary!\n");
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
	uint_least8_t* rsa_d_mem = malloc(rsa_d_bytes);
	if(!rsa_d_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for rsa d parameter!\n");
		free(rsa_n_mem); free(rsa_e_mem);
		return -3;
	}
	uint_least8_t* data_mem = malloc(data_bytes);
	if(!data_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for data!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem);
		return -3;
	}

	uint_fast8_t err_hold = _diode_Base64StrToBinary(rsa_n_str, rsa_n_mem, rsa_n_chars);
	err_hold |= _diode_Base64StrToBinary(rsa_e_str, rsa_e_mem, rsa_e_chars);
	err_hold |= _diode_Base64StrToBinary(rsa_d_str, rsa_d_mem, rsa_d_chars);
	err_hold |= _diode_Base64StrToBinary(data_str, data_mem, data_n_chars);	
		
	if(err_hold)
	{
		_DIODE_DEBUG_PRINT("Couldn't convert one or more b64 strings to binary!\n");
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
	if(EVP_PKEY_fromdata_init(pctx) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't initialize EVP_PKEY_CTX object for RSA parameters!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_CTX_free(pctx);
		return -6;
		
	}

	OSSL_PARAM* params = malloc(sizeof(*params) * 4 );
	if(!params)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for OSSL_PARAM objects!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_CTX_free(pctx);
		return -7;
	}

	params[0] = OSSL_PARAM_construct_BN("n", rsa_n_mem, rsa_n_bytes);
	params[1] = OSSL_PARAM_construct_BN("e", rsa_e_mem, rsa_e_bytes);
	params[2] = OSSL_PARAM_construct_BN("d", rsa_d_mem, rsa_d_bytes);
	params[3] = OSSL_PARAM_construct_end();

	EVP_PKEY* param_key;
	if(EVP_PKEY_fromdata(pctx, &param_key, EVP_PKEY_KEYPAIR, params) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't create parameters EVP_PKEY!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_CTX_free(pctx);
		OSSL_PARAM_free(params);
		return -8;
	}
	
	/* EVP_PKEY_print_private_fp(stdout, param_key, 2, NULL); */
	
	/* Now let's try decapsulation */

	/* Initialize for decapsulation */
	EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
	if(!dctx)
	{
		_DIODE_DEBUG_PRINT("CTX creation for decapsulation from key failed!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		OSSL_PARAM_free(params);
		return -9;
	}
	if(EVP_PKEY_decapsulate_init(dctx, NULL) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't initialize for decapsulation!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(dctx);
		return -10;
	}

	if(EVP_PKEY_CTX_set_kem_op(dctx, "RSASVE") <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't set key context for RSAVE operation!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(dctx);
		return -11;
	}

	/* Get secret binary size */
	size_t secret_bytes;
	if(EVP_PKEY_decapsulate(dctx, NULL, &secret_bytes, data_mem, data_bytes) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't get secret max memory size!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(dctx);
		return -12;
	}

	uint_least8_t* secret_mem = malloc(secret_bytes);
	if(!secret_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for secret!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(dctx);
		return -13;
	}

	/* Decapsulate */
	if(EVP_PKEY_decapsulate(dctx, secret_mem, &secret_bytes, data_mem, data_bytes) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't decapsulate!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(dctx);
		free(secret_mem);
		return -14;
	}
	
	/* Convert decapsulated binary secret to b64 string */
	uint_fast8_t free_secret_n_chars = 0;
	if(!secret_n_chars)
	{
		secret_n_chars = malloc(sizeof(*secret_n_chars));
		if(!secret_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for secret_n_chars!\n");
			free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
			EVP_PKEY_free(param_key);
			EVP_PKEY_CTX_free(pctx);
			OSSL_PARAM_free(params);
			EVP_PKEY_CTX_free(dctx);
			free(secret_mem);
			return -15;
		}
		free_secret_n_chars = 1;
	}

	*secret_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(secret_bytes);

	/* secret binary to b64 string conversion */
	*secret_str = malloc(*secret_n_chars + 1);
	if(!(*secret_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for data string!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(dctx);
		free(secret_mem);
		if(free_secret_n_chars)
			free(secret_n_chars);
		return -16;
	}

	if(_diode_BinaryToBase64Str(secret_mem, secret_bytes, *secret_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert wrapped data to b64 string!\n");
		free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
		EVP_PKEY_free(param_key);
		EVP_PKEY_CTX_free(pctx);
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(dctx);
		free(secret_mem);
		if(free_secret_n_chars)
			free(secret_n_chars);
		free(*secret_str);
		return -17;
	}

	/* Cleanup */
	free(rsa_n_mem); free(rsa_e_mem); free(rsa_d_mem); free(data_mem);
	EVP_PKEY_free(param_key);
	EVP_PKEY_CTX_free(pctx);
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(dctx);
	free(secret_mem);
	if(free_secret_n_chars)
		free(secret_n_chars);

	return 0;
}

#define GFBITS 13
#define SYS_N 4608
#define SYS_T 96
#define PK_NROWS (SYS_T*GFBITS) 
#define SYND_BYTES ((PK_NROWS + 7)/8)

/* This function does encapsulation using a public McEliece460896f key in b64 format, giving a shared secret and out in b64 format.
 * pub_key_str is the input for the public key string in b64 format, if it is null terminated then pub_key_chars can be given as zero, if not,
 * pub_key_chars must be the amount of characters in the string.
 * out_str and secret_str must not be NULL, and they will point to the shared secret and out, null terminated, b64 strings.
 * If you wish to know the the secret or out string char counts, you may give out_n_chars or secret_n_chars which will hold these values,
 * although if you don't wish the char counts, these can be given as NULL.
 *
 * Error Codes:
 * -1  A NULL pointer was provided to out_str, secret_str, or pub_key_str.
 * -2  Couldn't get size of memory for public key.
 * -3  Couldn't allocate memory for public key binary.
 * -4  Couldn't convert b64 public key to binary.
 * -5  Couldn't allocate memory for secret or out buffers.
 * -6  Couldn't allocate memory for out_n_chars.
 * -7  Couldn't allocate memory for out string.
 * -8  Couldn't convert out binary to a b64 string.
 * -9  Couldn't allocate memory for secret_n_chars.
 * -10 Couldn't allocate memory for secret string.
 * -11 Couldn't convert secret binary to a b64 string. 
 */
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_mceliece460896f_encapsulate(unsigned char* IN pub_key_str, uint_least32_t pub_key_chars,
		uint_least8_t** OUT out_str, uint_least32_t* OUT out_n_chars,
		uint_least8_t** OUT secret_str, uint_least32_t* OUT secret_n_chars)
{
	if((!out_str) | (!secret_str) | (!pub_key_str))
	{
		_DIODE_DEBUG_PRINT("A NULL pointer was provided to out_str, secret_str, or pub_key_str!\n");
		return -1;
	}

	if(!pub_key_chars)
		pub_key_chars = strlen((char*)pub_key_str);

	/* Base64 parameter strings to binary conversion */
	int_fast32_t pub_key_bytes = _diode_AmountOfBytesFromB64Str(pub_key_str, pub_key_chars);
	
	if(pub_key_bytes < 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't get size of memory for public key!\n");
		return -2;
	}

	uint_least8_t* pub_key_mem = malloc(pub_key_bytes);
	if(!pub_key_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for public key binary!\n");
		return -3;
	}

	if(_diode_Base64StrToBinary(pub_key_str, pub_key_mem, 0))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert b64 public key to binary!\n");
		free(pub_key_mem);
		return -4;
	}

	uint_least8_t* out_mem = malloc(SYND_BYTES);
	if(!out_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate out memory!\n");
		free(pub_key_mem);
		return -5;
	}

	uint_least8_t* secret_mem = malloc(32);
	if(!secret_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate secret memory!\n");
		free(pub_key_mem);
		free(out_mem);
		return -5;
	}

	/* Encapsulation */
	crypto_kem_enc(out_mem, secret_mem, pub_key_mem);

	/* out and secret to b64 */
	uint_fast8_t free_out_n_chars = 0;
	if(!out_n_chars)
	{
		out_n_chars = malloc(sizeof(*out_n_chars));
		if(!out_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for out_n_chars!\n");
			free(pub_key_mem);
			free(out_mem); free(secret_mem);
			return -6;
		}
		free_out_n_chars = 1;
	}

	*out_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(SYND_BYTES);
	*out_str = malloc((*out_n_chars) * sizeof(**out_str) + 1);
	if(!(*out_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for out string!\n");
		free(pub_key_mem);
		free(out_mem); free(secret_mem);
		if(free_out_n_chars)
			free(out_n_chars);
		return -7;
	}

	if(_diode_BinaryToBase64Str(out_mem, SYND_BYTES, *out_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert out binary to a b64 string!\n");
		free(pub_key_mem);
		free(out_mem); free(secret_mem);
		if(free_out_n_chars)
			free(out_n_chars);
		free(*out_str);
		return -8;
	}

	uint_fast8_t free_secret_n_chars = 0;
	if(!secret_n_chars)
	{
		secret_n_chars = malloc(sizeof(*secret_n_chars));
		if(!secret_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for secret_n_chars!\n");
			free(pub_key_mem);
			free(out_mem); free(secret_mem);
			if(free_out_n_chars)
				free(out_n_chars);
			free(*out_str);
			return -9;
		}
		free_secret_n_chars = 1;
	}

	*secret_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(32);
	*secret_str = malloc((*secret_n_chars) * sizeof(**secret_str) + 1);
	if(!(*secret_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for secret string!\n");
		free(pub_key_mem);
		free(out_mem); free(secret_mem);
		if(free_out_n_chars)
			free(out_n_chars);
		if(free_secret_n_chars)
			free(secret_n_chars);
		free(*out_str);
		return -10;
	}

	if(_diode_BinaryToBase64Str(secret_mem, 32, *secret_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert secret binary to a b64 string!\n");
		free(pub_key_mem);
		free(out_mem); free(secret_mem);
		if(free_out_n_chars)
			free(out_n_chars);
		if(free_secret_n_chars)
			free(secret_n_chars);
		free(*out_str);
		free(*secret_str);
		return -11;
	}

	free(pub_key_mem);
	free(out_mem); free(secret_mem);
	if(free_out_n_chars)
		free(out_n_chars);
	if(free_secret_n_chars)
		free(secret_n_chars);

	return 0;
}


/* This function does decapsulation using a private McEliece460896f key in b64 format, extracting the shared secret in b64 format.
 * prv_key_str is the input for the private key string in b64 format, if it is null terminated then prv_key_chars can be given as zero, if not,
 * prv_key_chars must be the amount of characters in the string.
 * Similary to prv_key_str and prv_key_chars, out_str is the input for the out in b64 format and out_n_chars the char count, if string isn't null terminated.
 * secret_str must not be NULL, and it will point to the shared secret, null terminated, b64 string.
 * If you wish to know the the secret char count, you may give secret_n_chars which will hold the count,
 * although if you don't wish the char count, secret_n_chars can be given as NULL.
 *
 * Error Codes:
 * -1  A NULL pointer was provided to out_str, secret_str, or prv_key_str.
 * -2  Couldn't get size of memory for private key or out.
 * -3  Couldn't allocate memory for out, secret or private key.
 * -4  Couldn't convert b64 private key or out to binary.
 * -5  Couldn't allocate memory for secret_n_chars.
 * -6  Couldn't allocate memory for secret string.
 * -7  Couldn't convert secret binary to a b64 string.
 */
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_mceliece460896f_decapsulate(unsigned char* IN prv_key_str, uint_least32_t prv_key_chars,
		unsigned char* IN out_str, uint_least32_t IN out_n_chars,
		uint_least8_t** OUT secret_str, uint_least32_t* OUT secret_n_chars)
{
	if((!out_str) | (!secret_str) | (!prv_key_str))
	{
		_DIODE_DEBUG_PRINT("A NULL pointer was provided to out_str, secret_str, or prv_key_str!\n");
		return -1;
	}

	if(!prv_key_chars)
		prv_key_chars = strlen((char*)prv_key_str);
	if(!out_n_chars)
		out_n_chars = strlen((char*)out_str);

	/* Base64 parameter strings to binary conversion */
	int_fast32_t prv_key_bytes = _diode_AmountOfBytesFromB64Str(prv_key_str, prv_key_chars);
	int_fast32_t out_bytes = _diode_AmountOfBytesFromB64Str(out_str, out_n_chars);
	
	if((prv_key_bytes < 0) | (out_bytes < 0))
	{
		_DIODE_DEBUG_PRINT("Couldn't get size of memory for private key or out!\n");
		return -2;
	}

	uint_least8_t* prv_key_mem = malloc(prv_key_bytes);
	if(!prv_key_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for private key binary!\n");
		return -3;
	}

	uint_least8_t* out_mem = malloc(out_bytes);
	if(!out_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for out binary!\n");
		free(prv_key_mem);
		return -3;
	}

	uint_least8_t* secret_mem = malloc(32);
	if(!secret_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for secret binary!\n");	
		free(prv_key_mem); free(out_mem);
		return -3;
	}

	if(_diode_Base64StrToBinary(prv_key_str, prv_key_mem, prv_key_chars))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert b64 private key to binary!\n");
		free(prv_key_mem); free(out_mem); free(secret_mem);
		return -4;
	}

	if(_diode_Base64StrToBinary(out_str, out_mem, out_n_chars))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert b64 out to binary!\n");
		free(prv_key_mem); free(out_mem); free(secret_mem);
		return -4;
	}

	/* Decapsulation */
	crypto_kem_dec(secret_mem, out_mem, prv_key_mem);
	
	/* Secret buffer to b64 string */
	uint_fast8_t free_secret_n_chars = 0;
	if(!secret_n_chars)
	{
		secret_n_chars = malloc(sizeof(*secret_n_chars));
		if(!secret_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for secret_n_chars!\n");
			free(prv_key_mem);
			free(out_mem); free(secret_mem);
			return -5;
		}
		free_secret_n_chars = 1;
	}

	*secret_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(32);
	*secret_str = malloc((*secret_n_chars) * sizeof(**secret_str) + 1);
	if(!(*secret_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for secret string!\n");
		free(prv_key_mem);
		free(out_mem); free(secret_mem);
		if(free_secret_n_chars)
			free(secret_n_chars);
		return -6;
	}

	if(_diode_BinaryToBase64Str(secret_mem, 32, *secret_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert secret binary to a b64 string!\n");
		free(prv_key_mem);
		free(out_mem); free(secret_mem);
		if(free_secret_n_chars)
			free(secret_n_chars);
		free(*secret_str);
		return -7;
	}

	free(prv_key_mem);
	free(out_mem); free(secret_mem);
	if(free_secret_n_chars)
		free(secret_n_chars);

	return 0;
}
