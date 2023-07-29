#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <_diode_Main.h>
#include <_diode_Utils.h>
#include <_diode_Keygen.h>

#include <operations.h>

#include <openssl/ssl.h>
#include <openssl/bn.h>

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

#ifndef __EMSCRIPTEN_PTHREADS__
int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_mceliece460896f_Keygen(uint_least8_t** OUT pub_key_str, uint_least32_t* OUT pub_n_chars,
                uint_least8_t** OUT prv_key_str, uint_least32_t* OUT prv_n_chars)
{
	*pub_key_str = "AAAAtttt";
	*prv_key_str = "Threads";

	return 0;
}
#else
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
#endif /* __EMSCRIPTEN_PTHREADS__ */
