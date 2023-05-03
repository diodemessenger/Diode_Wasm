#ifndef _DIODE_KEYGEN_H
#define _DIODE_KEYGEN_H

#include <_diode_Main.h>

#include <stdint.h>
#include <stdio.h>
#include <emscripten.h>

#ifndef EMSCRIPTEN_KEEPALIVE
#define EMSCRIPTEN_KEEPALIVE /* nothing */
#endif

extern int EMSCRIPTEN_KEEPALIVE _diode_Init();
extern int EMSCRIPTEN_KEEPALIVE _diode_Close();

/* This macro assumes there can't be an odd amount of nibbles representing a key,
 * returns base64 string size to represent the amount of data in bytes (size) given, without the null terminator */
#define _DIODE_BASE64STR_SIZE_FROM_NBYTES(size) ((((size) / 3)*4) + ((((size) % 3) > 0)<<2))

/* This function returns the amount of bytes (of 8bits size) necessary to represent the given string of base64.
 * If the string is not null terminated a size for the string must be given, otherwise size must be 0. 
 * This funcion expects the string to be UTF8 / ASCCII.
 * This function expects the size to ALWAYS be a multiple of four.
 * Returns the amount of bytes needed to represent the base64 string in binary, or a negative error code
 *
 * Error Codes
 * -1 The given string size isn't a multiple of 4.
 */
extern int_least32_t _diode_AmountOfBytesFromB64Str(const uint_least8_t* const IN str, const uint_least32_t size);

/* Convertes a base64 string (str) to its binary representation, writing it in mem.
 * It is the Caller's responsability to ensure mem has anough space for the binary,
 * to find this necessary size for a given b64 string, you can use _diode_Base64StrSizeInBinaryBytes() or _diode_Base64StrSizeInBinaryBytes_wStrSize()
 * str_size is needed if the string is not null terminated, if it is, str_size must be 0 . The str_size must be a multiple of four.
 * */
extern int_fast8_t _diode_Base64StrToBinary(const uint_least8_t* const IN str, uint_least8_t* const OUT mem, int_least32_t str_size);

/* Function writes the given binary data (mem) to str as a base64 string.
 * It is the caller's responsability to make sure str has enough space for the binary data in b64 format + a null terminator
 * To find the b64 str size without the null terminator use _DIODE_BASE64STR_SIZE_FROM_NBYTES
 *
 * Error Codes:
 * -1 A NULL pointer was given as mem or str
 */
extern int_fast8_t _diode_BinaryToBase64Str(const uint_least8_t* const IN mem, uint_least32_t mem_size,
		uint_least8_t* const OUT str);

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

/* Generates a signature from a given string of a private key in base64 chars and a message,
 * Takes in the string (msg) to make the signature , private key string (b64_key),
 * and allocates a string pointer, to be returned by the function, with the signature.
 * If the msg_len is given to be 0, then msg is expected to be null terminated to find the size.
 * key bits lenght MUST be divisable by 8.
 *
 * free() must be called to free the returned string memory by the caller.
 * If the singning failed NULL is returned.
 */
extern uint_least8_t* EMSCRIPTEN_KEEPALIVE _diode_SignString_wED25519PrivateBase64Key(const unsigned char* const IN msg, size_t msg_len,
		const unsigned char* const IN b64_key);

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
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_VerifySig_wED25519PublicBase64Key(const unsigned char* const IN sig,
		const unsigned char* const IN b64_key, const unsigned char* const IN msg);


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
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_encapsulate(unsigned char* IN rsa_n_str, uint_least32_t rsa_n_chars,
		unsigned char* IN rsa_e_str, uint_least32_t rsa_e_chars,
		uint_least8_t** OUT out_str, uint_least32_t* OUT out_n_chars,
		uint_least8_t** OUT secret_str, uint_least32_t* OUT secret_n_chars);

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
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_decapsulate(unsigned char* IN rsa_n_str, uint_least32_t rsa_n_chars,
		unsigned char* IN rsa_e_str, uint_least32_t rsa_e_chars,
		unsigned char* IN rsa_d_str, uint_least32_t rsa_d_chars,
		uint_least8_t* IN data_str, uint_least32_t data_n_chars,
		uint_least8_t** OUT secret_str, uint_least32_t* OUT secret_n_chars);


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
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_encrypt_wB64(unsigned char* IN rsa_n_str, uint_least32_t rsa_n_chars,
		unsigned char* IN rsa_e_str, uint_least32_t rsa_e_chars,
		uint_least8_t* IN data_str, uint_least32_t data_n_chars,
		uint_least8_t** OUT out_str, uint_least32_t* out_n_chars);


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
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_decrypt_wB64(unsigned char* IN rsa_n_str, uint_least32_t rsa_n_chars,
		unsigned char* IN rsa_e_str, uint_least32_t rsa_e_chars,
		unsigned char* IN rsa_d_str, uint_least32_t rsa_d_chars,
		uint_least8_t* IN data_str, uint_least32_t data_n_chars,
		uint_least8_t** OUT out_str, uint_least32_t* out_n_chars);

/* WIP */
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_mceliece460896f_encrypt_wB64(unsigned char* IN pub_key_str, uint_least32_t pub_key_chars,
		uint_least8_t* IN data_str, uint_least32_t data_n_chars,
		uint_least8_t** OUT out_str, uint_least32_t* out_n_chars);

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
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_mceliece460896f_encapsulate(unsigned char* IN pub_key_str, uint_least32_t pub_key_chars,
		uint_least8_t** OUT out_str, uint_least32_t* OUT out_n_chars,
		uint_least8_t** OUT secret_str, uint_least32_t* OUT secret_n_chars);

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
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_mceliece460896f_decapsulate(unsigned char* IN prv_key_str, uint_least32_t prv_key_chars,
		unsigned char* IN out_str, uint_least32_t IN out_n_chars,
		uint_least8_t** OUT secret_str, uint_least32_t* OUT secret_n_chars);


#endif /* _DIODE_KEYGEN_H */
