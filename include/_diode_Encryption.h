#ifndef _DIODE_ENCRYPTION_H
#define _DIODE_ENCRYPTION_H

#include <emscripten.h>
#include <stdint.h>

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

#endif /* _DIODE_ENCRYPTION_H */
