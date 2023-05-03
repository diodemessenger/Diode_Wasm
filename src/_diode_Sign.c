#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <_diode_Main.h>
#include <_diode_Utils.h>

#include <_diode_Sign.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

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
