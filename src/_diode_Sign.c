#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <_diode_Main.h>
#include <_diode_Utils.h>

#include <_diode_Sign.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* Signs the given message with a private key in base64,
 * Takes in the message string (msg) to make the digest (dig), signing with private key string (prv_key_str),
 * and allocates a string stored in *dig, with the digest.
 * If the msg_len/prv_key_chars is given to be 0, then msg/prv_key_str is expected to be null terminated to find the size.
 *
 * free() must be called to free the returned string memory by the caller.
 * 
 * error codes:
 * -1  msg, prv_key_str or dig was given as a NULL pointer.
 * -2  Invalid private key given.
 * -3  Couldn't allocate private key memory.
 * -4  Couldn't convert private key to binary.
 * -5  Couldn't create EVP_PKEY object.
 * -6  Couldn't create EVP_MD_CTX object.
 * -7  Couldn't initialize CTX.
 * -8  Couldn't get digest size.
 * -9  Couldn't allocate digest memory.
 * -10 Couldn't sign.
 * -11 Couldn't allocate memory for digest string.
 * -12 Couldn't convert signature binary to b64 string.
 */
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_SignString_wED25519PrivateBase64Key(const unsigned char* const IN msg, size_t msg_len,
		const unsigned char* const IN prv_key_str, uint_least32_t prv_key_chars,
		uint_least8_t** OUT dig)
{
	if((!msg) | (!prv_key_str) | (!dig))
	{
		_DIODE_DEBUG_PRINT("A NULL pointer was given as the msg, key or digest string pointer!\n");
		return -1;
	}

	if(!prv_key_chars)
	{
		prv_key_chars = strlen((char*)prv_key_str);
	}

	uint_least8_t* mem;
	EVP_PKEY* prv_key = NULL;

	/* Base64 key string to binary conversion */
	int_fast32_t n_bytes = _diode_AmountOfBytesFromB64Str(prv_key_str, prv_key_chars);
	
	if(n_bytes == -1)
	{
		_DIODE_DEBUG_PRINT("Invalid private key given!!!\n");
		return -2;
	}

	/* Buffer for key binary */
	mem = malloc(n_bytes);
	if(!mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate private key memory!\n");
		return -3;
	}

	if(_diode_Base64StrToBinary(prv_key_str, mem, prv_key_chars))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert private key to binary!\n");
		free(mem);
		return -4;
	}

	/* Creating Key and CTX objects */
	prv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, mem, n_bytes);
	if(!prv_key)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_PKEY object!\n");
		free(mem);
		return -5;
	}

	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_MD_CTX object!\n");
		free(mem);
		EVP_PKEY_free(prv_key);
		return -6;
	}

	/* Initialization for signing */
	if(!msg_len)
		msg_len = strlen((char*)msg);
	if(!EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, prv_key))
	{
		_DIODE_DEBUG_PRINT("Couldn't initialize CTX!\n");
		free(mem);
		EVP_PKEY_free(prv_key);
		EVP_MD_CTX_free(md_ctx);
		return -7;
	}

	/* Calculate the required size for the digest by passing a NULL */
	size_t dig_len = 0;
	if(!EVP_DigestSign(md_ctx, NULL, &dig_len, msg, msg_len))
	{
		_DIODE_DEBUG_PRINT("Couldn't get digest size!\n");
		free(mem);
		EVP_PKEY_free(prv_key);
		EVP_MD_CTX_free(md_ctx);
		return -8;
	}

	free(mem);
	mem = OPENSSL_zalloc(dig_len);
	if(!mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate digest memory!\n");
		EVP_PKEY_free(prv_key);
		EVP_MD_CTX_free(md_ctx);
		return -9;
	}

	/* Signing */
	if(!EVP_DigestSign(md_ctx, mem, &dig_len, msg, msg_len))
	{
		_DIODE_DEBUG_PRINT("Couldn't sign!\n");
		EVP_PKEY_free(prv_key);
		EVP_MD_CTX_free(md_ctx);
		OPENSSL_free(mem);
		return -10;
	}

	*dig = malloc(_DIODE_BASE64STR_SIZE_FROM_NBYTES(dig_len) + 1);
	if(!(*dig))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for digest string!\n");
		EVP_PKEY_free(prv_key);
		EVP_MD_CTX_free(md_ctx);
		OPENSSL_free(mem);
		return -11;
	}

	/* Signature to b64 conversion */
	if(_diode_BinaryToBase64Str(mem, dig_len, *dig))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert signature binary to b64 string!\n");
		EVP_PKEY_free(prv_key);
		EVP_MD_CTX_free(md_ctx);
		OPENSSL_free(mem);
		free(*dig);
		return -12;
	}

	EVP_PKEY_free(prv_key);
	EVP_MD_CTX_free(md_ctx);
	OPENSSL_free(mem);
	return 0;
}


/* The functions verifies the given base64 encoded signature (sig) against the given message (msg) with the base64 encoded (public) key (b64_key).
 * All strings must be null terminated.
 * returns 1 on success, 0 on failure, negative value for an error
 *
 * error codes:
 * -1  either sig, b64_key or msg was given as a null pointer.
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
 * -12 Couldn't allocate memory for signature string.
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
