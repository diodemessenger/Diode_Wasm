#include <_diode_Main.h>
#include <_diode_Keygen.h>
#include <crypto_kem_mceliece460896f.h>
#include <operations.h>

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


#undef KAT

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
	//unsigned char** rsa_primes = malloc(sizeof(*rsa_primes));

	unsigned char** out_str = malloc(sizeof(*out_str));
	unsigned char** secret_str = malloc(sizeof(*secret_str));
	unsigned char** de_secret_str = malloc(sizeof(*de_secret_str));

	_diode_ED25519_Keygen(pub_str, &pub_chars, prv_str, &prv_chars);

	printf("PUB chars: %d | PRV chars: %d\n", pub_chars, prv_chars);
	printf("PUB ED25519 KEY: %s\n", *pub_str);
	printf("PRV ED25519 KEY: %s\n", *prv_str);

	uint_least8_t* dig = _diode_SignString_wED25519PrivateBase64Key(msg, 0, *prv_str);
	if(dig == NULL)
		return -1;

	printf("Digest: %s\n", dig);
	printf("Verify Success? : %d\n", _diode_VerifySig_wED25519PublicBase64Key(dig, *pub_str, msg));

	puts("Now RSA!");

	if(_diode_RSA_Keygen(rsa_n, &n_chars, rsa_e, &e_chars, rsa_d, &d_chars, NULL, NULL, 2048, 3, 73673))
	{
		return 1;
	}

	printf("PARAM N chars: %d | PARAM E chars: %d | PARAM D chars: %d\n", n_chars, e_chars, d_chars);
	printf("RSA N   PARAM: %s\n", *rsa_n);
	printf("RSA E   PARAM: %s\n", *rsa_e);
	printf("RSA D   PARAM: %s\n", *rsa_d);
	
	//printf("RSA P   PARAM: %s\n", rsa_primes[0]);
	//printf("RSA Q   PARAM: %s\n", rsa_primes[1]);
	//printf("RSA R_I PARAM: %s\n", rsa_primes[2]);
	
	puts("Now Encapsulation!");

	if(_diode_RSA_encapsulate(*rsa_n, 0, *rsa_e, 0, out_str, &out_chars, secret_str, &secret_chars))
	{
		return 1;
	}

	printf("OUT chars: %d | SECRET chars: %d\n", out_chars, secret_chars);
	printf("OUT   : %s\n", *out_str);
	printf("SECRET: %s\n", *secret_str);

	puts("Now Decapsulation!");

	if(_diode_RSA_decapsulate(*rsa_n, 0, *rsa_e, 0, *rsa_d, 0, *out_str, 0, de_secret_str, NULL))
	{
		return 1;
	}

	printf("SECRET: %s\n", *de_secret_str);

	puts("Now Encryption!");

	unsigned char* encrypt_data = (unsigned char*)"AQABff55AQABff55AQABff55";
	uint_least8_t** encrypt_str = malloc(sizeof(*encrypt_str));

	printf("ORIGINAL DATA: %s\n", encrypt_data);

	uint_least32_t data_size = 24;
	if(_diode_RSA_encrypt_wB64(*rsa_n, 0, *rsa_e, 0, encrypt_data, data_size, encrypt_str, NULL))
	{
		return 1;
	}

	printf("ENCRYPTED DATA: %s\n", *encrypt_str);

	puts("Now Decryption!");

	uint_least8_t** decrypted_data = malloc(sizeof(*decrypted_data));

	if(_diode_RSA_decrypt_wB64(*rsa_n, 0, *rsa_e, 0, *rsa_d, 0, *encrypt_str, 0, decrypted_data, NULL))
	{
		return 1;
	}

	printf("DECRYPTED DATA: %s\n", *decrypted_data);

	free(*decrypted_data);
	free(decrypted_data);
	free(*encrypt_str);
	free(encrypt_str);

	free(*rsa_n); free(*rsa_e); free(*rsa_d);
	free(rsa_n); free(rsa_e); free(rsa_d);
	free(*out_str);
	free(*secret_str);
	free(*de_secret_str);


	free(*prv_str);
	free(*pub_str);	
	puts("Now McEliece Key Generation");

	_diode_mceliece460896f_Keygen(pub_str, &pub_chars, prv_str, &prv_chars);
	printf("PUB chars: %d | PRV chars: %d\n", pub_chars, prv_chars);
	printf("PUB McEliece KEY: %s\n", *pub_str);
	printf("PRV McEliece KEY: %s\n", *prv_str);

	puts("Now McEliece Encapsulation");

	_diode_mceliece460896f_encapsulate(*pub_str, pub_chars, out_str, &out_chars, secret_str, &secret_chars);
	printf("OUT chars: %d | SECRET chars: %d\n", out_chars, secret_chars);
	printf("OUT   : %s\n", *out_str);
	printf("SECRET: %s\n", *secret_str);
	
	puts("Now McEliece Decapsulation");

	_diode_mceliece460896f_decapsulate(*prv_str, prv_chars, *out_str, out_chars, de_secret_str, NULL);
	printf("SECRET: %s\n", *de_secret_str);
	

	free(*de_secret_str);
	free(de_secret_str);
	free(*prv_str);
	free(*pub_str);
	free(prv_str);
	free(pub_str);
	free(*out_str);
	free(out_str);
	free(*secret_str);
	free(secret_str);

	_diode_Close();

	
	puts("main() is done!\n");
	*/
	
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

/* This function Generates the RSA parameters, where the n and e parameters are the public key and all of them the private key (minimum needed are n,e,d)
 * bits determines the bit size, must be higher than 512, a multiple of 512 or 0 for default of 2048 bits.
 * primes determines the amount of prime factors to be selected, it must be between 2 and 10, or 0 for a default of 2 primes,
 * altough with higher bit sizes less primes are suported, and if too high key generation will fail!
 * e input is the public exponent value you want, it must be 65537 or higher and odd. 0 can be given for a default value of 65537.
 * *rsa_n_str, *rsa_e_str and *rsa_d_str will hold the n,e,d parameters in b64 format. rsa_e_str is not needed, so it can be NULL, as you know the e value.
 * rsa_primes_str will hold the primes strings, rsa_primes_str[primes], rsa_primes_str[0] for p prime, rsa_primes_str[1] for q prime and etc...
 * rsa_primes_str can also be NULL if you don't want the primes.
 * These strings will be NULL terminated, but if you wish you can provide rsa_n_chars, rsa_e_chars, rsa_d_chars,
 * where the size of the b64 parameter strings in b64 chars will be written to *rsa_n_chars, *rsa_e_chars and *rsa_d_chars.
 * rsa_primes_chars[primes], will hold the char counts of each one of the primes strings, rsa_primes_char[0] for p prime chars, etc...
 * rsa_primes_chars must be pointing to enough allocated memory for all the primes char counts integer objects!!!! This memory must be handled by the caller.
 * If you don't wish to know the sizes, NULL can be given rsa_n_chars, rsa_e_chars, rsa_d_chars and rsa_primes_chars.
 *
 * Error Codes:
 * -1  A NULL pointer was given to rsa_n_str or rsa_d_str.
 * -2  Invalid number of primes. Must be between 2 and 10, higher bit sizes will have lower limits.
 * -3  e value is too low. Must be above 65537 and odd.
 * -4  e value isn't odd.
 * -5  RSA bit size must be a multiple of 512.
 * -6  Couldn't create EVP_PKEY_CTX object for RSA.
 * -7  Couldn't initialize key context object for RSA.
 * -8  Couldn't set parameters for key context object for RSA.
 * -9  Couldn't generate RSA keys
 * -10 Couldn't create EVP_PKEY object, RSA keys couldn't be generated.
 * -11 Couldn't allocate the memory for the prime BIGNUM pointer objects.
 * -12 Couldn't allocate the memory for one of the RSA BIGNUM objects.
 * -13 Couldn't extract RSA n parameter.
 * -14 Couldn't extract RSA e parameter.
 * -15 Couldn't extract RSA d parameter.
 * -16 Couldn't extract one of the RSA primes.
 * -17 Couldn't allocate memory for the RSA prime buffers pointer.
 * -18 Couldn't allocate the memory for one of the RSA parameters.
 * -19 One of the parameter buffers was too small.
 * -20 Couldn't allocate memory for rsa_n_chars, rsa_e_chars or rsa_d_chars or rsa_prime_chars.
 * -21 Couldn't allocate memory for n parameter string.
 * -22 Couldn't convert n parameter binary to base64.
 * -23 Couldn't allocate memory for e parameter string.
 * -24 Couldn't convert e parameter binary to base64.
 * -25 Couldn't allocate memory for d parameter string.
 * -26 Couldn't convert d parameter binary to base64.
 * -27 Couldn't allocate memory for a prime string.
 * -28 Couldn't convert a prime binary to base64.
 */
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_Keygen(uint_least8_t** OUT rsa_n_str, uint_least32_t* rsa_n_chars,
		uint_least8_t** OUT rsa_e_str, uint_least32_t* rsa_e_chars,
		uint_least8_t** OUT rsa_d_str, uint_least32_t* rsa_d_chars,
		uint_least8_t** OUT rsa_primes_str, uint_least32_t* rsa_primes_chars, /* rsa_prime_chars must hold enough memory for the amount of primes */
		uint_fast32_t bits, uint_fast32_t primes, uint_fast32_t e)
{
	if((!rsa_n_str) | (!rsa_d_str))
	{
		_DIODE_DEBUG_PRINT("A NULL pointer was given to rsa_n_str or rsa_d_str!\n");
		return -1;
	}

	/* Check number of primes requested */
	if((primes < 1) | (primes > 10))
	{
		_DIODE_DEBUG_PRINT("Invalid number of primes! Must be between 2 and 10, higher bit sizes will have lower limits.\n");
		return -2;
	}
	else if(!primes)
		primes = 2;
	
	/* Check e parameter value */
	if(e < 65537)
	{
		_DIODE_DEBUG_PRINT("e value is too low! Must be above 65537 and odd.\n");
		return -3;
	}
	if(!e)
		e = 65537;

	if(!(e%2))
	{
		_DIODE_DEBUG_PRINT("e value isn't odd!\n");
		return -4;
	}

	/* Check bit size */
	if(bits % 512)
	{
		_DIODE_DEBUG_PRINT("RSA bit size must be a multiple of 512!");
		return -5;
	}

	if(!bits)
		bits = 2048;

	/* Creating Key Context for RSA generation */
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if(!ctx)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_PKEY_CTX object for RSA!\n");
		return -6;
	}

	if(EVP_PKEY_keygen_init(ctx) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't initialize key context object for RSA!\n");
		EVP_PKEY_CTX_free(ctx);
		return -7;
	}

	OSSL_PARAM params[4];
	params[0] = OSSL_PARAM_construct_uint("bits", &bits);
	params[1] = OSSL_PARAM_construct_uint("primes", &primes);
	params[2] = OSSL_PARAM_construct_uint("e", &e);
	params[3] = OSSL_PARAM_construct_end();
	
	if(!EVP_PKEY_CTX_set_params(ctx, params))
	{
		_DIODE_DEBUG_PRINT("Couldn't set parameters for key context object for RSA!\n");
		EVP_PKEY_CTX_free(ctx);
		return -8;
	}

	EVP_PKEY* keys;
	if(EVP_PKEY_generate(ctx, &keys) <= 0)
	{
		_DIODE_DEBUG_PRINT("Couldn't generate RSA keys!\n");
		EVP_PKEY_CTX_free(ctx);
		return -9;
	}

	if(!keys)
	{
		_DIODE_DEBUG_PRINT("Couldn't create EVP_PKEY object, RSA keys couldn't be generated!\n");
		EVP_PKEY_CTX_free(ctx);
		return -10;
	}

	/* EVP_PKEY_print_private_fp(stdout, keys, 2, NULL); */

	/* Now let's get BIGNUM parameters of RSA */
	BIGNUM *BN_n, *BN_e, *BN_d;
	BIGNUM** BN_primes = NULL;
	if(rsa_primes_str)
	{
		BN_primes = malloc(primes * sizeof(*BN_primes));
		if(!BN_primes)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the prime BIGNUM pointer objects!\n");
			EVP_PKEY_CTX_free(ctx);
			EVP_PKEY_free(keys);
			free(BN_primes);
			return -11;
		}
	}

	BN_n = BN_new();
	if(!BN_n)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the n RSA parameter BIGNUM object!\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(keys);
		free(BN_primes);
		return -12;
	}
	if(rsa_e_str)
	{
		BN_e = BN_new();
		if(!BN_e)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the e RSA parameter BIGNUM object!\n");
			EVP_PKEY_CTX_free(ctx);
			EVP_PKEY_free(keys);
			BN_free(BN_n);
			free(BN_primes);
			return -12;
		}
	}
	BN_d = BN_new();
	if(!BN_d)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the d RSA parameter BIGNUM object!\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(keys);
		BN_free(BN_n);
		if(rsa_e_str) {BN_free(BN_e);}
		free(BN_primes);
		return -12;
	}
	
	int_fast8_t p_count;
	if(rsa_primes_str)
	{
		p_count = primes;
		while(p_count)
		{
			p_count--;
			BN_primes[p_count] = BN_new();
			if(!BN_primes[p_count])
			{
				_DIODE_DEBUG_PRINT("Couldn't allocate the memory for one of RSA prime BIGNUM objects!\n");
				EVP_PKEY_CTX_free(ctx);
				EVP_PKEY_free(keys);
				BN_free(BN_n); BN_free(BN_d);
				if(rsa_e_str) {BN_free(BN_e);}
				p_count++;
				while(p_count < primes)
				{
				      BN_free(BN_primes[p_count]);
				      p_count++;
				}
				free(BN_primes);
				return -12;
			}
		}
	}

	if(!EVP_PKEY_get_bn_param(keys, "n", &BN_n))
	{
		_DIODE_DEBUG_PRINT("Couldn't extract RSA n parameter!\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(keys);
		BN_free(BN_n); BN_free(BN_d);
		if(rsa_e_str) {BN_free(BN_e);}
		for(p_count = 0; p_count < primes; p_count++)
		      BN_free(BN_primes[p_count]);
		free(BN_primes);
		return -13;
	}
	if(rsa_e_str)
	{
		if(!EVP_PKEY_get_bn_param(keys, "e", &BN_e))
		{
			_DIODE_DEBUG_PRINT("Couldn't extract RSA e parameter!\n");
			EVP_PKEY_CTX_free(ctx);
			EVP_PKEY_free(keys);
			BN_clear_free(BN_n); BN_free(BN_d);
			if(rsa_e_str) {BN_free(BN_e);}
			for(p_count = 0; p_count < primes; p_count++)
			      BN_free(BN_primes[p_count]);
			free(BN_primes);
			return -14;
		}
	}
	if(!EVP_PKEY_get_bn_param(keys, "d", &BN_d))
	{
		_DIODE_DEBUG_PRINT("Couldn't extract RSA d parameter!\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(keys);
		BN_clear_free(BN_n); BN_free(BN_d);
		if(rsa_e_str) {BN_clear_free(BN_e);}
		for(p_count = 0; p_count < primes; p_count++)
		      BN_free(BN_primes[p_count]);
		free(BN_primes);
		return -15;
	}

	if(rsa_primes_str)
	{
		char prime_factor_str[12] = {'r', 's', 'a', '-', 'f', 'a', 'c', 't', 'o', 'r', '1', '\0'};
		for(p_count = 0; p_count < primes; p_count++)
		{
			prime_factor_str[10] =(char)(p_count + 49); /* integer to char + 1 conversion */
			if(!EVP_PKEY_get_bn_param(keys, prime_factor_str, &(BN_primes[p_count])))
			{
				_DIODE_DEBUG_PRINT("Couldn't extract one of the RSA primes!\n");
				EVP_PKEY_CTX_free(ctx);
				EVP_PKEY_free(keys);
				BN_clear_free(BN_n); BN_clear_free(BN_d);
				if(rsa_e_str) {BN_clear_free(BN_e);}
				for(p_count = 0; p_count < primes; p_count++)
				      BN_clear_free(BN_primes[p_count]);
				free(BN_primes);
				return -16;
			}
		}
	}
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(keys);

	/* Now let's get the binary from the BIGNUM's */
	size_t rsa_n_size, rsa_e_size, rsa_d_size;
	size_t* rsa_primes_size;
	if(rsa_primes_str)
		rsa_primes_size = malloc(primes * sizeof(*rsa_primes_size));


	/* Getting lenght sizes, this assumes the word size is a multiple of the bit lenght of these parameters*/
	rsa_n_size = BN_num_bytes(BN_n);
	if(rsa_e_str)
		rsa_e_size = BN_num_bytes(BN_e);
	rsa_d_size = BN_num_bytes(BN_d);
	if(rsa_primes_str)
	{
		for(p_count = 0; p_count < primes; p_count++)
			rsa_primes_size[p_count] = BN_num_bytes(BN_primes[p_count]);
	}

	uint_least8_t** rsa_primes_mem;
	if(rsa_primes_str)
	{
		rsa_primes_mem = malloc(primes * sizeof(*rsa_primes_mem));
		if(!rsa_primes_mem)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for the RSA prime buffers pointer!\n");
			BN_clear_free(BN_n); BN_clear_free(BN_d);
			if(rsa_e_str) {BN_clear_free(BN_e);}
			for(p_count = 0; p_count < primes; p_count++)
			      BN_clear_free(BN_primes[p_count]);
			free(BN_primes);
			free(rsa_primes_size);
			return -17;
		}
	}

	uint_least8_t* rsa_n_mem = malloc(rsa_n_size);
	if(!rsa_n_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the RSA n parameter binary!\n");
		BN_clear_free(BN_n); BN_clear_free(BN_d);
		if(rsa_e_str) {BN_clear_free(BN_e);}
		for(p_count = 0; p_count < primes; p_count++)
		      BN_clear_free(BN_primes[p_count]);
		free(BN_primes);
		free(rsa_primes_size);
		free(rsa_primes_mem);
		return -18;
	}
	uint_least8_t* rsa_e_mem = NULL;
	if(rsa_e_str)
	{
		rsa_e_mem = malloc(rsa_e_size);
		if(!rsa_e_mem)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the RSA e parameter binary!\n");
			BN_clear_free(BN_n); BN_clear_free(BN_d);
			if(rsa_e_str) {BN_clear_free(BN_e);}
			for(p_count = 0; p_count < primes; p_count++)
			      BN_clear_free(BN_primes[p_count]);
			free(BN_primes);
			free(rsa_primes_size);
			free(rsa_n_mem);
			free(rsa_primes_mem);
			return -18;
		}
	}
	uint_least8_t* rsa_d_mem = malloc(rsa_d_size);
	if(!rsa_d_mem)
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate the memory for the RSA d parameter binary!\n");
		BN_clear_free(BN_n); BN_clear_free(BN_d);
		if(rsa_e_str) { BN_clear_free(BN_e); free(rsa_e_mem); }
		for(p_count = 0; p_count < primes; p_count++)
		      BN_clear_free(BN_primes[p_count]);
		free(BN_primes);
		free(rsa_primes_size);
		free(rsa_n_mem); 
		free(rsa_primes_mem);
		return -18;
	}
	
	if(rsa_primes_str)
	{
		for(p_count = 0; p_count < primes; p_count++)
		{
			rsa_primes_mem[p_count] = malloc(rsa_primes_size[p_count]); 
			if(!rsa_primes_mem[p_count])
			{
				_DIODE_DEBUG_PRINT("Couldn't allocate the memory for a RSA prime binary!\n");
				BN_clear_free(BN_n); BN_clear_free(BN_d);
				if(rsa_e_str) { BN_clear_free(BN_e); free(rsa_e_mem); }
				for(uint_fast8_t p_p_count = 0; p_p_count < primes; p_p_count++)
				      BN_clear_free(BN_primes[p_p_count]);
				free(BN_primes);
				free(rsa_primes_size);
				free(rsa_n_mem); free(rsa_d_mem);
				p_count--;
				while(0 <= p_count)
				{
					free(rsa_primes_mem[p_count]);
					p_count--;
				}
				free(rsa_primes_mem);
				return -18;
			}
		}
	}

	if(BN_bn2nativepad(BN_n, rsa_n_mem, rsa_n_size) < 0)
	{
		_DIODE_DEBUG_PRINT("Parameter n buffer size is too small!\n");
		if(rsa_e_str) {BN_clear_free(BN_e); free(rsa_e_mem); }
		BN_clear_free(BN_n); BN_clear_free(BN_d);
		for(p_count = 0; p_count < primes; p_count++)
		{
			BN_clear_free(BN_primes[p_count]);
			free(rsa_primes_mem[p_count]);
		}
		free(BN_primes);
		free(rsa_primes_size);
		free(rsa_n_mem); free(rsa_d_mem);
		free(rsa_primes_mem);
		return -19;
	}
	BN_clear_free(BN_n);

	if(rsa_e_str)
	{
		if(BN_bn2nativepad(BN_e, rsa_e_mem, rsa_e_size) < 0)
		{
			_DIODE_DEBUG_PRINT("Parameter e buffer size is too small!\n");
			BN_clear_free(BN_d);
			if(rsa_e_str) {BN_clear_free(BN_e); free(rsa_e_mem); }
			for(p_count = 0; p_count < primes; p_count++)
			{
				BN_clear_free(BN_primes[p_count]);
				free(rsa_primes_mem[p_count]);
			}
			free(BN_primes);
			free(rsa_primes_size);
			free(rsa_n_mem); free(rsa_d_mem);
			free(rsa_primes_mem);
			return -19;
		}
		BN_clear_free(BN_e);
	}

	if(BN_bn2nativepad(BN_d, rsa_d_mem, rsa_d_size) < 0)
	{
		_DIODE_DEBUG_PRINT("Parameter d buffer size is too small!\n");
		BN_clear_free(BN_d);
		for(p_count = 0; p_count < primes; p_count++)
		{
			BN_clear_free(BN_primes[p_count]);
			free(rsa_primes_mem[p_count]);
		}
		free(BN_primes);
		free(rsa_primes_size);
		free(rsa_n_mem); free(rsa_d_mem);
		if(rsa_e_str) { free(rsa_e_mem); }
		free(rsa_primes_mem);
		return -19;
	}
	BN_clear_free(BN_d);

	if(rsa_primes_str)
	{
		for(p_count = 0; p_count < primes; p_count++)
		{
			if(BN_bn2nativepad(BN_primes[p_count], rsa_primes_mem[p_count], rsa_primes_size[p_count]) < 0)
			{
				_DIODE_DEBUG_PRINT("One of primes buffer size is too small!\n");
				for(p_count = 0; p_count < primes; p_count++)
				{
					BN_clear_free(BN_primes[p_count]);
					free(rsa_primes_mem[p_count]);
				}
				free(BN_primes);
				free(rsa_primes_size);
				free(rsa_n_mem); free(rsa_d_mem);
				if(rsa_e_str) { free(rsa_e_mem); }
				free(rsa_primes_mem);
				return -19;
			}
			BN_clear_free(BN_primes[p_count]);
		}
		free(BN_primes);
	}

	/* Setting up for b64 conversion */

	uint_fast32_t free_rsa_n_chars = 0;
	uint_fast32_t free_rsa_e_chars = 0;
	uint_fast32_t free_rsa_d_chars = 0;
	uint_fast32_t free_rsa_primes_chars = 0;

	if(!rsa_n_chars)
	{
		rsa_n_chars = malloc(sizeof(*rsa_n_chars));
		if(!rsa_n_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for rsa_n_chars!\n");
			for(p_count = 0; p_count < primes; p_count++)
				free(rsa_primes_mem[p_count]);
			free(rsa_primes_mem);
			free(rsa_n_mem); free(rsa_d_mem);
			if(rsa_e_str) { free(rsa_e_mem); }
			free(rsa_primes_size);
			return -20;
		}
		free_rsa_n_chars = 1;
	}

	if((!rsa_e_chars) && rsa_e_str)
	{
		rsa_e_chars = malloc(sizeof(*rsa_e_chars));
		if(!rsa_e_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for rsa_e_chars!\n");
			for(p_count = 0; p_count < primes; p_count++)
				free(rsa_primes_mem[p_count]);
			free(rsa_primes_mem);
			free(rsa_n_mem); free(rsa_d_mem);
			if(rsa_e_str) { free(rsa_e_mem); }
			free(rsa_primes_size);
			if(free_rsa_n_chars)
				free(rsa_n_chars);
			return -20;
		}
		free_rsa_e_chars = 1;
	}

	if(!rsa_d_chars)
	{
		rsa_d_chars = malloc(sizeof(*rsa_d_chars));
		if(!rsa_d_chars)
		{
			_DIODE_DEBUG_PRINT("Couldn't allocate memory for rsa_d_chars!\n");
			for(p_count = 0; p_count < primes; p_count++)
				free(rsa_primes_mem[p_count]);
			free(rsa_primes_mem);
			free(rsa_n_mem); free(rsa_d_mem);
			if(rsa_e_str) { free(rsa_e_mem); }
			free(rsa_primes_size);
			if(free_rsa_n_chars)
				free(rsa_n_chars);
			if(free_rsa_e_chars)
				free(rsa_e_chars);
			return -20;
		}
		free_rsa_d_chars = 1;
	}

	if(rsa_primes_str)
	{
		if(!rsa_primes_chars)
		{
			rsa_primes_chars = malloc(primes * sizeof(*rsa_primes_chars));
			if(!rsa_primes_chars)
			{
				_DIODE_DEBUG_PRINT("Couldn't allocate memory for rsa_primes_chars!\n");
				for(p_count = 0; p_count < primes; p_count++)
					free(rsa_primes_mem[p_count]);
				free(rsa_primes_mem);
				free(rsa_n_mem); free(rsa_d_mem);
				if(rsa_e_str) { free(rsa_e_mem); }
				free(rsa_primes_size);
				if(free_rsa_n_chars)
					free(rsa_n_chars);
				if(free_rsa_e_chars)
					free(rsa_e_chars);
				if(free_rsa_d_chars)
					free(rsa_d_chars);
				return -20;

			}
			free_rsa_primes_chars = 1;
		}
		for(p_count = 0; p_count < primes; p_count++)
		{
			rsa_primes_chars[p_count] = _DIODE_BASE64STR_SIZE_FROM_NBYTES(rsa_primes_size[p_count]);
		}
	}


	*rsa_n_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(rsa_n_size);
	if(rsa_e_str) { *rsa_e_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(rsa_e_size); }
	*rsa_d_chars = _DIODE_BASE64STR_SIZE_FROM_NBYTES(rsa_d_size);

	/* Now let's allocate strings memory and do conversion */

	*rsa_n_str = malloc(*rsa_n_chars + 1);
	if(free_rsa_n_chars)
		free(rsa_n_chars);
	if(!(*rsa_n_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for n parameter string!\n");
		for(p_count = 0; p_count < primes; p_count++)
			free(rsa_primes_mem[p_count]);
		free(rsa_primes_mem);
		free(rsa_n_mem); free(rsa_d_mem);
		if(rsa_e_str) { free(rsa_e_mem); }
		free(rsa_primes_size);
		if(free_rsa_e_chars)
			free(rsa_e_chars);
		if(free_rsa_d_chars)
			free(rsa_d_chars);
		if(free_rsa_primes_chars)
			free(rsa_primes_chars);
		return -21;
	}

	if(_diode_BinaryToBase64Str(rsa_n_mem, rsa_n_size, *rsa_n_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert n parameter binary to base64!\n");
		for(p_count = 0; p_count < primes; p_count++)
			free(rsa_primes_mem[p_count]);
		free(rsa_primes_mem);
		free(rsa_n_mem); free(rsa_d_mem);
		if(rsa_e_str) { free(rsa_e_mem); }
		free(rsa_primes_size);
		if(free_rsa_e_chars)
			free(rsa_e_chars);
		if(free_rsa_d_chars)
			free(rsa_d_chars);
		if(free_rsa_primes_chars)
			free(rsa_primes_chars);
		free(*rsa_n_str);
		return -22;
	}
	free(rsa_n_mem);


	*rsa_e_str = malloc(*rsa_e_chars + 1);
	if(free_rsa_e_chars)
		free(rsa_e_chars);
	if(!(*rsa_e_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for e parameter string!\n");
		for(p_count = 0; p_count < primes; p_count++)
			free(rsa_primes_mem[p_count]);
		free(rsa_primes_mem);
		free(rsa_d_mem);
		if(rsa_e_str) { free(rsa_e_mem); }
		free(rsa_primes_size);
		if(free_rsa_d_chars)
			free(rsa_d_chars);
		if(free_rsa_primes_chars)
			free(rsa_primes_chars);
		free(*rsa_n_str);
		return -23;
	}

	if(_diode_BinaryToBase64Str(rsa_e_mem, rsa_e_size, *rsa_e_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert e parameter binary to base64!\n");
		for(p_count = 0; p_count < primes; p_count++)
			free(rsa_primes_mem[p_count]);
		free(rsa_primes_mem);
		free(rsa_d_mem);
		free(rsa_primes_size);
		if(free_rsa_d_chars)
			free(rsa_d_chars);
		if(free_rsa_primes_chars)
			free(rsa_primes_chars);
		free(*rsa_n_str); free(*rsa_e_str);
		return -24;
	}
	if(rsa_e_str) { free(rsa_e_mem); }


	*rsa_d_str = malloc(*rsa_d_chars + 1);
	if(free_rsa_d_chars)
		free(rsa_d_chars);
	if(!(*rsa_d_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't allocate memory for d parameter string!\n");
		for(p_count = 0; p_count < primes; p_count++)
			free(rsa_primes_mem[p_count]);
		free(rsa_primes_mem);
		free(rsa_d_mem);
		free(rsa_primes_size);
		if(free_rsa_primes_chars)
			free(rsa_primes_chars);
		free(*rsa_n_str); free(*rsa_e_str);
		return -25;
	}

	if(_diode_BinaryToBase64Str(rsa_d_mem, rsa_d_size, *rsa_d_str))
	{
		_DIODE_DEBUG_PRINT("Couldn't convert d parameter binary to base64!\n");
		for(p_count = 0; p_count < primes; p_count++)
			free(rsa_primes_mem[p_count]);
		free(rsa_primes_mem);
		free(rsa_d_mem);
		free(rsa_primes_size);
		if(free_rsa_primes_chars)
			free(rsa_primes_chars);
		free(*rsa_n_str); free(*rsa_e_str); free(*rsa_d_str);
		return -26;
	}
	free(rsa_d_mem);

	if(rsa_primes_str)
	{
		for(p_count = 0; p_count < primes; p_count++)
		{
			rsa_primes_str[p_count] = malloc(rsa_primes_chars[p_count] + 1);
			if(!rsa_primes_str[p_count])
			{
				_DIODE_DEBUG_PRINT("Couldn't allocate memory for a prime string!\n");
				for(int_fast8_t p_p_count = p_count; 0 <= p_p_count; p_p_count--)
					free(rsa_primes_mem[p_p_count]);
				free(rsa_primes_mem);
				free(rsa_primes_size);
				if(free_rsa_primes_chars)
					free(rsa_primes_chars);
				free(*rsa_n_str); free(*rsa_e_str); free(*rsa_d_str);
				p_count--;
				while(0 <= p_count)
				{
					free(rsa_primes_str[p_count]);
					p_count--;
				}
				return -27;
			}
			
			if(_diode_BinaryToBase64Str(rsa_primes_mem[p_count], rsa_primes_size[p_count], rsa_primes_str[p_count]))
			{
				_DIODE_DEBUG_PRINT("Couldn't convert a prime binary to base64!\n");
				for(int_fast8_t p_p_count = p_count; 0 <= p_p_count; p_p_count--)
					free(rsa_primes_mem[p_p_count]);
				free(rsa_primes_mem);
				free(rsa_primes_size);
				if(free_rsa_primes_chars)
					free(rsa_primes_chars);
				free(*rsa_n_str); free(*rsa_e_str); free(*rsa_d_str);
				p_count--;
				while(0 <= p_count)
				{
					free(rsa_primes_str[p_count]);
					p_count--;
				}
				return -28;	
			}
			free(rsa_primes_mem[p_count]);
		}
	}

	free(rsa_primes_mem);
	free(rsa_primes_size);
	if(free_rsa_primes_chars)
		free(rsa_primes_chars);
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

//extern int crypto_kem_enc(unsigned char *c, unsigned char *key, const unsigned char *pk);
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


//extern int crypto_kem_dec(unsigned char *key, const unsigned char *c, const unsigned char *sk);
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
