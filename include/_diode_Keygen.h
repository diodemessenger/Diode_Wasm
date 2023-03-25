#ifndef _DIODE_KEYGEN_H
#define _DIODE_KEYGEN_H

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


/* This function Generates a random pair of RSA Keys, where the n and e parameters are the public key and the d parameter is the private key.
 * bits determines the bit size, must be a multiple of 1024 or 0 for default of 2048 bits.
 * *rsa_n_str, rsa_e_str and rsa_d_str will hold the n,e,d parameters in b64 format.
 * These strings will be NULL terminated, but if you wish you can provide rsa_n_chars, rsa_e_chars, rsa_d_chars,
 * where the size of the b64 parameter stirngs in b64 chars will be written to *rsa_n_chars, *rsa_e_chars and *rsa_d_chars.
 * If you don't wish to know the sizes, NULL can be given rsa_n_chars, rsa_e_chars and rsa_d_chars.
 *
 * Error Codes:
 * -1  A NULL pointer was given for one of the string pointers.
 * -2  RSA bit size must be a multiple of 1024.
 * -3  Couldn't create EVP_PKEY_CTX object for RSA.
 * -4  Couldn't initialize key context object for RSA.
 * -5  Couldn't set parameters for key context object for RSA.
 * -6  Couldn't generate RSA keys.
 * -7  Couldn't create EVP_PKEY object, RSA keys couldn't be generated.
 * -8  Couldn't allocate the memory for the n, e or d RSA parameter BIGNUM object.
 * -9  Couldn't extract RSA n parameter.
 * -10 Couldn't extract RSA e parameter.
 * -11 Couldn't extract RSA d parameter.
 * -12 Couldn't allocate the memory for the RSA n, e or d parameter binary.
 * -13 Didn't copy the correct size of bytes from the n, e or d paramter BIGNUM to binary buffer.
 * -14 Couldn't allocate memory for rsa_n_chars, rsa_e_chars or rsa_d_chars.
 * -15 Couldn't allocate memory for n parameter string.
 * -16 Couldn't convert n parameter binary to base64.
 * -17 Couldn't allocate memory for e parameter string.
 * -18 Couldn't convert e parameter binary to base64.
 * -19 Couldn't allocate memory for d parameter string.
 * -20 Couldn't convert d parameter binary to base64.
 */
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_Keygen(uint_least8_t** OUT rsa_n_str, uint_least32_t* rsa_n_chars,
		uint_least8_t** OUT rsa_e_str, uint_least32_t* rsa_e_chars,
		uint_least8_t** OUT rsa_d_str, uint_least32_t* rsa_d_chars,
		uint_least32_t bits);


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
 */
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_RSA_encapsulate(unsigned char* IN rsa_n_str, uint_least32_t rsa_n_chars,
		unsigned char* IN rsa_e_str, uint_least32_t rsa_e_chars,
		uint_least8_t** OUT out_str, uint_least32_t* OUT out_n_chars,
		uint_least8_t** OUT secret_str, uint_least32_t* OUT secret_n_chars);

#endif /* _DIODE_KEYGEN_H */
