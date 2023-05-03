#ifndef _DIODE_KEM_H
#define _DIODE_KEM_H

#include <emscripten.h>
#include <stdint.h>

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

#endif /* _DIODE_KEM_H */
