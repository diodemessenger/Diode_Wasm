#include <_diode_Main.h>
#include <_diode_Keygen.h>
#include <crypto_kem_mceliece460896f.h>

#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Defines for code readability */
#define IN
#define OUT

static uint_least8_t *PRIVATE_KEY;
static uint_least8_t *PUBLIC_KEY;
static size_t *PRIVATE_LEN;
static size_t *PUBLIC_LEN;

int main(void)
{
	/*
	_diode_Init();
	unsigned char* msg = (unsigned char*) "Hello Wasm!";

	_diode_ED25519_Keygen();

	uint_least8_t* prv = malloc(_diode_ED25519_PrivateKeySizeInB64Chars() + 1);
	uint_least8_t* pub = malloc(_diode_ED25519_PublicKeySizeInB64Chars() + 1);
	_diode_ED25519_CopyKeys_Base64Str(prv, pub);

	printf("Key: %s\n", prv);

	uint_least8_t* dig = NULL;

	dig = _diode_SignString_wED25519PrivateBase64Key(msg, 0, prv);

	printf("Digest: %s\n", dig);

	printf("Success? : %d\n", _diode_VerifySig_wED25519PublicBase64Key(dig, pub, msg));

	free(prv);
	free(pub);
	
	printf("PRV Size: %d | PUB Size: %d\n", _diode_mceliece460896f_PrivateKeySizeInB64Chars() + 1,
			_diode_mceliece460896f_PublicKeySizeInB64Chars() + 1);
	prv = malloc(_diode_mceliece460896f_PrivateKeySizeInB64Chars() + 1);
	pub = malloc(_diode_mceliece460896f_PublicKeySizeInB64Chars() + 1);

	_diode_mceliece460896f_Keygen(prv, pub);
	printf("Pub Key: %s\n", pub);
	printf("Prv Key: %s\n", prv);

	_diode_Close();
	*/	
	return 0;
}


int _diode_Init()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	PRIVATE_KEY = malloc(1);
	PUBLIC_KEY = malloc(1);
	PRIVATE_LEN = malloc(sizeof(size_t));
	PUBLIC_LEN = malloc(sizeof(size_t));

	return 0;
}

int _diode_Close()
{
	ENGINE_cleanup();
	CONF_modules_unload(1);
	EVP_cleanup();
	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
	CRYPTO_cleanup_all_ex_data();

	free(PUBLIC_KEY);
	free(PRIVATE_KEY);
	free(PUBLIC_LEN);
	free(PRIVATE_LEN);

	return 0;
}


/* Function writes the given binary data (mem) to str as a base64 sting. If either mem or str is NULL, this function does nothing
 * It is the caller's responsability to make sure str has enough space for the binary data in b64 format + a null terminator
 * To find the b64 str size without the null terminator use _DIODE_BASE64STR_SIZE_FROM_NBYTES */
void _diode_BinaryToBase64Str(const uint_least8_t* const IN mem, uint32_t size, uint_least8_t* const OUT str)
{
	if(!mem | !str)
	{
		return;
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
	while(i < (size - 2))
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
	remainder = size % 3;
	above0 = remainder > 0;
	above1 = remainder > 1;
	is1 = remainder & 1;
	str[j] = (uint_least8_t)(mem[i+above0]>>2)*above0;
	str[j + above0] = (uint_least8_t)((mem[i+above0]&0x3)<<4)*above0 | (mem[i+above0+above1]>>4)*above1;
	str[j + (above0<<1)] = (uint_least8_t)((mem[i+above0+above1]&0xF)<<2)*above1 | 61*is1;
	str[j + (above0*3)] = (uint_least8_t)61*above0;
	str[j + (above0<<2)] = (uint_least8_t)'\0';

	/* Convert Base64 binary values to Base64 chars in ascci/UTF-8 */
	i = ((size/3)*4) + (above0<<1) + above1; /* Amount of Base64 chars to convert */ 
	do
	{
		i--;
		str[i] = (uint_least8_t)((str[i]<26)*(65+str[i])) |
			(((str[i]>25) & (str[i]<52))*(71+str[i])) |
			(((str[i]>51) & (str[i]<62))*(str[i]-4)) |
			((str[i]==62)*43) | ((str[i]==63)*47);
	} while(i);
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
int_fast32_t  _diode_Base64StrToBinary(const uint_least8_t* const IN str, uint_least8_t* const OUT mem, int_least32_t str_size)
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


/* This function assumes there can't be an odd amount of nibbles representing a key,
 * returns base64 string size to represent the private key binary value, without the null terminator */
uint_least32_t _diode_ED25519_PrivateKeySizeInB64Chars(void)
{
	/* Add 4/3 more chars to fit sets of 3 chars with 6 bit word Base64 chars,
	 * if there is a remainder, word misalignment, add 4 more characters for padding chars and extra necessary space */
	return (((*PRIVATE_LEN / 3)*4) + (((*PRIVATE_LEN % 3) > 0)<<2));
}

/* This function assumes there can't be an odd amount of nibbles representing a key,
 * returns base64 string size to represent the public key binary value, without the null terminator */
uint_least32_t _diode_ED25519_PublicKeySizeInB64Chars(void)
{
	return (((*PUBLIC_LEN / 3)*4) + (((*PUBLIC_LEN % 3) > 0)<<2));
}

/* This function converts the keys binary to base64 strings and copies them over to prvk for the private key and pubk for the public key.
 * If there are no generated keys, it will do nothing. At the end it will free the Keys memory.
 * It is the caller's responsibility to make sure the strings have enough space for the base64 strings + a null terminator
 * The space for these strings minus the null terminator can be found with _diode_ED25519_PrivateKeySizeInB64Chars()
 * and _diode_ED25519_PublicteKeySizeInB64Chars.
 * It is the CALLER'S RESPONSIBILITY to always free the memory of *all* pointers, or make sure they are freed.
 */
void _diode_ED25519_CopyKeys_Base64Str(unsigned char* const OUT prvk, unsigned char* const OUT pubk)
{
	if(!PRIVATE_KEY)
	{
		_DIODE_DEBUG_PRINT("Tried to copy Private ED25519 key when none was generated!\n");
		return;
	}

	if(!PUBLIC_KEY)
	{
		_DIODE_DEBUG_PRINT("Tried to copy Public ED25519 key when none was generated!\n");
		return;
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
	while(i < (*PRIVATE_LEN - 2))
	{
		prvk[j++] = (uint_least8_t)(PRIVATE_KEY[i]>>2);
		prvk[j++] = (uint_least8_t)((PRIVATE_KEY[i]&0x3)<<4) | (PRIVATE_KEY[i+1]>>4);
		prvk[j++] = (uint_least8_t)((PRIVATE_KEY[i+1]&0xF)<<2) | (PRIVATE_KEY[i+2]>>6);
		prvk[j++] = (uint_least8_t)(PRIVATE_KEY[i+2]&0x3F);
		i += 3;
	}

	/* If you can read this you deserve a medal */
	/* This does the shifting when necessary, puts in the '='(61) characters when necessary, and avoids reading memory out of bounds :) */
	i--;
	remainder = *PRIVATE_LEN % 3; /* integer division modulo expected, altough no difference in functionality */
	above0 = remainder > 0;
	above1 = remainder > 1;
	is1 = remainder & 1;
	prvk[j] = (uint_least8_t)(PRIVATE_KEY[i+above0]>>2)*above0;
	prvk[j + above0] = (uint_least8_t)((PRIVATE_KEY[i+above0]&0x3)<<4)*above0 | (PRIVATE_KEY[i+above0+above1]>>4)*above1;
	prvk[j + (above0<<1)] = (uint_least8_t)((PRIVATE_KEY[i+above0+above1]&0xF)<<2)*above1 | 61*is1;
	prvk[j + ((above0<<1)|1)] = (uint_least8_t)61*above0;
	prvk[j + (above0<<2)] = (uint_least8_t)'\0';

	/* Convert Base64 binary values to Base64 chars in ascci/UTF-8 */
	i = (((*PRIVATE_LEN)/3)*4) + (above0<<1) + above1; /* Amount of Base64 chars to convert */ 
	do
	{
		i--;
		prvk[i] = (uint_least8_t)((prvk[i]<26)*(65+prvk[i])) |
			(((prvk[i]>25) & (prvk[i]<52))*(71+prvk[i])) |
			(((prvk[i]>51) & (prvk[i]<62))*(prvk[i]-4)) |
			((prvk[i]==62)*43) | ((prvk[i]==63)*47);
	} while(i);

	/* Now do the same for the public key */

	j = 0;
	i = 0;
	while(i < (*PRIVATE_LEN - 2))
	{
		pubk[j++] = (uint_least8_t)(PUBLIC_KEY[i]>>2);
		pubk[j++] = (uint_least8_t)((PUBLIC_KEY[i]&0x3)<<4) | (PUBLIC_KEY[i+1]>>4);
		pubk[j++] = (uint_least8_t)((PUBLIC_KEY[i+1]&0xF)<<2) | (PUBLIC_KEY[i+2]>>6);
		pubk[j++] = (uint_least8_t)(PUBLIC_KEY[i+2]&0x3F);
		i += 3;
	}

	i--;
	remainder = *PUBLIC_LEN % 3; /* integer division modulo expected, altough no difference in functionality */
	above0 = remainder > 0;
	above1 = remainder > 1;
	is1 = remainder & 1;
	pubk[j] = (uint_least8_t)(PUBLIC_KEY[i+above0]>>2)*above0;
	pubk[j + above0] = (uint_least8_t)((PUBLIC_KEY[i+above0]&0x3)<<4)*above0 | (PUBLIC_KEY[i+above0+above1]>>4)*above1;
	pubk[j + (above0<<1)] = (uint_least8_t)((PUBLIC_KEY[i+above0+above1]&0xF)<<2)*above1 | 61*is1;
	pubk[j + ((above0<<1)|1)] = (uint_least8_t)61*above0;
	pubk[j + (above0<<2)] = (uint_least8_t)'\0';

	i = (((*PUBLIC_LEN)/3)*4) + (above0<<1) + above1; /* Amount of Base64 chars to convert */ 
	do
	{
		i--;
		pubk[i] = (uint_least8_t)((pubk[i]<26)*(65+pubk[i])) |
			(((pubk[i]>25) & (pubk[i]<52))*(71+pubk[i])) |
			(((pubk[i]>51) & (pubk[i]<62))*(pubk[i]-4)) |
			((pubk[i]==62)*43) | ((pubk[i]==63)*47);
	} while(i);

	/* Free Keys memory */

	free(PUBLIC_KEY);
	free(PRIVATE_KEY);
	PUBLIC_KEY = NULL;
	PRIVATE_KEY = NULL;
	
	*PRIVATE_LEN = 0;
	*PUBLIC_LEN = 0;
}


/* Generates a random pair of ED25519 Keys, deletes old ones if still in memory
 *
 * Error Codes:
 * -1 Couldn't create the object with the generated keys
 * -2 Couldn't allocate memory for PRIVATE_KEY
 * -3 Couldn't allocate memory for PUBLIC_KEY
 * -4 Couldn't get private key binary
 * -5 Couldn't get public key binary
 */
int_fast32_t _diode_ED25519_Keygen()
{
	EVP_PKEY *keys;
	keys = EVP_PKEY_Q_keygen(NULL,NULL,"ED25519");

	if(!keys)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_PKEY object, ED25519 keys couldn't be generated!\n");
		return -1;
	}

	#ifdef _DIODE_DEBUG_LVL
	EVP_PKEY_print_private_fp(stdout, keys, 0, NULL);
	#endif

	/* Getting lenght sizes */
	EVP_PKEY_get_raw_private_key(keys, NULL, PRIVATE_LEN);
	EVP_PKEY_get_raw_public_key(keys, NULL, PUBLIC_LEN);
	
	if(PRIVATE_KEY)
		free(PRIVATE_KEY);
	if(PUBLIC_KEY)
		free(PUBLIC_KEY);

	PUBLIC_KEY = malloc(sizeof(char) * (*PUBLIC_LEN));
	PRIVATE_KEY = malloc(sizeof(char) * (*PRIVATE_LEN));

	if(!PRIVATE_KEY)
	{
		if(keys)
			EVP_PKEY_free(keys);

		_DIODE_DEBUG_PRINT("Couldn't allocate memory for PRIVATE_KEY!\n");
		return -2;
	}
	if(!PUBLIC_KEY)
	{
		if(keys)
			EVP_PKEY_free(keys);

		_DIODE_DEBUG_PRINT("Couldn't allocate memory for PUBLIC_KEY!\n");
		return -3;
	}

	/* Writing binary of keys */
	if(!EVP_PKEY_get_raw_private_key(keys, PRIVATE_KEY, PRIVATE_LEN))
	{
		if(PRIVATE_KEY)
			free(PRIVATE_KEY);
		if(PUBLIC_KEY)
			free(PUBLIC_KEY);
		if(keys)
			EVP_PKEY_free(keys);

		_DIODE_DEBUG_PRINT("Couldn't get Private key binary!\n");
		return -4;
	}

        if(!EVP_PKEY_get_raw_public_key(keys, PUBLIC_KEY, PUBLIC_LEN))
	{
		if(PRIVATE_KEY)
			free(PRIVATE_KEY);
		if(PUBLIC_KEY)
			free(PUBLIC_KEY);
		if(keys)
			EVP_PKEY_free(keys);

		_DIODE_DEBUG_PRINT("Couldn't get Public key binary!\n");
		return -5;
	}

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
 */
uint_least8_t* _diode_SignString_wED25519PrivateBase64Key(const unsigned char* const IN msg, size_t msg_len,
		const unsigned char* const IN b64_key)
{
	size_t sig_len = 0;
	uint_least8_t* OUT sig_str = NULL;
	uint_least8_t* mem;

	EVP_PKEY *prv_key = NULL;

	/* Base64 key string to binary conversion */
	uint_fast32_t n_bytes = _diode_AmountOfBytesFromB64Str(b64_key, 0);
	mem = malloc(n_bytes);
	_diode_Base64StrToBinary(b64_key, mem, 0);

	prv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, mem, n_bytes);

	#ifdef _DIODE_DEBUG_LVL 
	printf("SIGN KEY:\n");
	EVP_PKEY_print_private_fp(stdout, prv_key, 0, NULL);
	#endif

	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
	if(!msg_len)
	{
		msg_len = strlen((char*)msg);
	}

	EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, prv_key);
	/* Calculate the requires size for the signature by passing a NULL buffer */
	EVP_DigestSign(md_ctx, NULL, &sig_len, msg, msg_len);
	free(mem);
	mem = OPENSSL_zalloc(sig_len);
	EVP_DigestSign(md_ctx, mem, &sig_len, msg, msg_len);

	sig_str = malloc(_DIODE_BASE64STR_SIZE_FROM_NBYTES(sig_len) + 1);
	_diode_BinaryToBase64Str(mem, sig_len, sig_str);

	EVP_MD_CTX_free(md_ctx);
	OPENSSL_free(mem);

	EVP_PKEY_free(prv_key);

	return sig_str;
}


/* The functions verifies the given base64 encoded signature (sig) against the given message (msg) with the base64 encoded (public) key (b64_key).
 * All strings must be null terminated.
 * returns 1 on success, 0 on failure */
uint_fast8_t _diode_VerifySig_wED25519PublicBase64Key(const unsigned char* const IN sig, const unsigned char* const IN b64_key,
		const unsigned char* const IN msg)
{
	uint_least8_t success = 0; /* 0 is for failure */
	uint_least8_t* key_mem;
	uint_least8_t* sig_mem;
	EVP_PKEY *pub_key;

	/* Base64 key string to binary conversion */
	uint_fast32_t key_n_bytes = _diode_AmountOfBytesFromB64Str(b64_key,0);
	key_mem = malloc(key_n_bytes);
	_diode_Base64StrToBinary(b64_key, key_mem, 0);

	/* Base64 signature to binary conversion */	
	uint_fast32_t sig_n_bytes = _diode_AmountOfBytesFromB64Str(sig,0);
	sig_mem = malloc(sig_n_bytes);
	_diode_Base64StrToBinary(sig, sig_mem, 0);

	/* Public Key Creation */
	pub_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key_mem, key_n_bytes);

	#ifdef _DIODE_DEBUG_LVL 
	printf("VERIFY KEY:\n");
	EVP_PKEY_print_public_fp(stdout, pub_key, 0, NULL);
	#endif

	/* Verification */
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
	EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pub_key);
	success = EVP_DigestVerify(md_ctx, sig_mem, sig_n_bytes, msg, strlen((char*)msg));

	/* Cleanup */
	free(key_mem);
	free(sig_mem);
	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(pub_key);

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

/* The following functions return the size of McEliece's Public and Private Key size in b64 chars */
uint_least32_t _diode_mceliece460896f_PublicKeySizeInB64Chars(void)
{
	return _DIODE_BASE64STR_SIZE_FROM_NBYTES(MCELIECE460896F_PUBLICKEYBYTES);
}


uint_least32_t _diode_mceliece460896f_PrivateKeySizeInB64Chars(void)
{
	return _DIODE_BASE64STR_SIZE_FROM_NBYTES(MCELIECE460896F_SECRETKEYBYTES);
}


/* Generates a McEliece's 460896f Key pair, writes to prv_key and pub_key.
 * prv_key and pub_key must have enough space for the base64 representation of the keys, plus a null terminator,
 * _diode_mceliece460896f_b64PublicKeySizeInChars() and _diode_mceliece460896f_b64PrivateKeySizeInChars(), to get these key sizes,
 * altough they should be the same value every time.
 *
 * Error Codes:
 * -1 Couldn't allocate memory for the Private key
 * -2 Couldn't allocate memory for the Public key
 * -3 Couldn't generate Key Pair
 */
int_fast8_t _diode_mceliece460896f_Keygen(uint_least8_t* const OUT prv_key, uint_least8_t* const OUT pub_key)
{
	*PRIVATE_LEN = MCELIECE460896F_SECRETKEYBYTES;
	*PUBLIC_LEN = MCELIECE460896F_PUBLICKEYBYTES;

	if(PRIVATE_KEY)
		free(PRIVATE_KEY);
	if(PUBLIC_KEY)
		free(PUBLIC_KEY);

	PRIVATE_KEY = malloc(MCELIECE460896F_SECRETKEYBYTES);
	if (!PRIVATE_KEY)
	{
		_DIODE_DEBUG_PRINT("Couldn't Allocate McEliece Private key!\n");
		return -1;
	}
	PUBLIC_KEY = malloc(MCELIECE460896F_PUBLICKEYBYTES);
	if (!PUBLIC_KEY)
	{
		_DIODE_DEBUG_PRINT("Couldn't Allocate McEliece Public key!\n");
		return -2;
	}

	if(crypto_kem_mceliece460896f_ref_keypair(PUBLIC_KEY, PRIVATE_KEY))
	{
		_DIODE_DEBUG_PRINT("Couldn't generate McEliece key pair!!\n");
		return -3;
	}

	_diode_BinaryToBase64Str(PRIVATE_KEY, MCELIECE460896F_SECRETKEYBYTES, prv_key);
	_diode_BinaryToBase64Str(PUBLIC_KEY, MCELIECE460896F_PUBLICKEYBYTES, pub_key);

	return 0;
}
