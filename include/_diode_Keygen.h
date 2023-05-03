#ifndef _DIODE_KEYGEN_H
#define _DIODE_KEYGEN_H

#include <stdint.h>
#include <emscripten.h>

/* This function Generates a random pair of ED25519 Keys.
 * *pub_key_str will hold the public key in b64 format and *prv_key_str will hold the private key in b64 format.
 * These strings will be NULL terminated, but if you wish you can provide pub_n_chars and prv_n_chars,
 * where the size of the public key in b64 chars will be written to *pub_n_chars and the same for the private key to *prv_n_chars.
 * If you don't wish to know the sizes, NULL can be given to pub_n_chars and/or prv_n_chars.
 *
 * Error Codes:
 * -1  A NULL pointer was given for pub_key_str or prv_key_str.
 * -2  Couldn't create EVP_PKEY object.
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
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_ED25519_Keygen(uint_least8_t** OUT pub_key_str, uint_least32_t* OUT pub_n_chars,
		uint_least8_t** OUT prv_key_str, uint_least32_t* OUT prv_n_chars);


/* Generates a McEliece's 460896f Key pair, writes to *prv_key_str and *pub_key_str the b64 representations, so these objects can't be NULL.
 * The size in b64 chars of the corresponding strings are written to *pub_n_chars and *prv_n_chars,
 * the key strings will be NULL terminated, so these size objects can be NULL if you don't need the char count.
 *
 * Error Codes:
 * -1  Either pub_key_str or prv_key_str was given as NULL.
 * -2  Couldn't allocate memory for the Private key.
 * -3  Couldn't allocate memory for the Public key.
 * -4  Couldn't generate McEliece key pair.
 * -5  Couldn't allocate memory for prv_n_chars.
 * -6  Couldn't allocate memory for pub_n_chars.
 * -7  Couldn't allocate memory for private key string.
 * -8  Couldn't allocate memory for public key string.
 * -9  Couldn't convert private key to b64.
 * -10 Couldn't convert public key to b64.
 */
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_mceliece460896f_Keygen(uint_least8_t** OUT pub_key_str, uint_least32_t* OUT pub_n_chars,
                uint_least8_t** OUT prv_key_str, uint_least32_t* OUT prv_n_chars);

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
 * -1  A NULL pointer was given to rsa_n_str, rsa_d_str or rsa_primes.
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
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_Keygen(uint_least8_t** OUT rsa_n_str, uint_least32_t* rsa_n_chars,
		uint_least8_t** OUT rsa_e_str, uint_least32_t* rsa_e_chars,
		uint_least8_t** OUT rsa_d_str, uint_least32_t* rsa_d_chars,
		uint_least8_t** OUT rsa_primes_str, uint_least32_t* rsa_primes_chars, /* rsa_prime_chars must hold enough memory for the amount of primes */
		uint_fast32_t bits, uint_fast32_t primes, uint_fast32_t e);


#endif /* _DIODE_KEYGEN_H */
