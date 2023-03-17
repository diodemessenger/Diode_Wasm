#ifndef _DIODE_KEYGEN_H
#define _DIODE_KEYGEN_H

#include <stdint.h>
#include <stdio.h>

int _diode_Init();
int _diode_Close();

/* This macro assumes there can't be an odd amount of nibbles representing a key,
 * returns base64 string size to represent the amount of data in bytes (size) given, without the null terminator */
#define _DIODE_BASE64STR_SIZE_FROM_NBYTES(size) ((((size) / 3)*4) + ((((size) % 3) > 0)<<2))

/* Convertes a base64 string (str) to its binary representation, writing it in mem.
 * It is the Caller's responsability to ensure mem has anough space for the binary,
 * to find this necessary size for a given b64 string, you can use _diode_Base64StrSizeInBinaryBytes() or _diode_Base64StrSizeInBinaryBytes_wStrSize()
 * str_size is needed if the string is not null terminated, if it is, str_size must be 0 . The str_size must be a multiple of four.
 * */
int_fast32_t _diode_Base64StrToBinary(const uint_least8_t* const IN str, uint_least8_t* const OUT mem, int_least32_t str_size);

/* This function writes the given binary data (mem) to str as a base64 sting. If either mem or str is NULL, this function does nothing
 * It is the caller's responsability to make sure str has enough space for the binary data in b64 format + a null terminator
 * To find the b64 str size without the null terminator use _DIODE_BASE64STR_SIZE_FROM_NBYTES */
void _diode_BinaryToBase64Str(const uint_least8_t* const IN mem, uint32_t size, uint_least8_t* const OUT str);

/* This function returns the amount of bytes (of 8bits size) necessary to represent the given string of base64.
 * If the string is not null terminated a size for the string must be given, otherwise size must be 0. 
 * This funcion expects the string to be UTF8 / ASCCII.
 * This function expects the size to ALWAYS be a multiple of four.
 * Returns the amount of bytes needed to represent the base64 string in binary, or a negative error code
 *
 * Error Codes
 * -1 The given string size isn't a multiple of 4.
 */
int_least32_t _diode_AmountOfBytesFromB64Str(const uint_least8_t* const IN str, const uint_least32_t size);


/* This function assumes there can't be an odd amount of nibbles representing a key,
 * returns base64 string size to represent the private key binary value, without the null terminator */
uint_least32_t _diode_ED25519_PrivateKeySizeInB64Chars(void);

/* This function assumes there can't be an odd amount of nibbles representing a key,
 * returns base64 string size to represent the public key binary value, without the null terminator */
uint_least32_t _diode_ED25519_PublicKeySizeInB64Chars(void);

/* This function converts the keys binary to base64 strings and copies them over to prvk for the private key and pubk for the public key.
 * At the end it will free the Keys memory.
 * It is the caller's responsibility to make sure the strings have enough space for the base64 strings + a null terminator
 * The space for these strings minus the null terminator can be found with _diode_ED25519_Base64PublicKeySize() and _diode_ED25519_Base64PrivateKeySize().
 * It is the CALLER'S RESPONSIBILITY to always free the memory of *all* pointers, or make sure they are freed.
 */
void _diode_ED25519_CopyKeys_Base64Str(unsigned char* const OUT prvk, unsigned char* const OUT pubk);

/* Generates a random pair of ED25519 Keys, deletes old ones if still in memory
 *
 * Error Codes:
 * -1 Couldn't create the object with the generated keys
 * -2 Couldn't allocate memory for PRIVATE_KEY
 * -3 Couldn't allocate memory for PUBLIC_KEY
 * -4 Couldn't get private key binary
 * -5 Couldn't get public key binary
 */
int_fast32_t _diode_ED25519_Keygen();

/* Generates a signature from a given string of a private key in base64 chars and a message,
 * Takes in the string (msg) to make the signature , private key string (b64_key),
 * and allocates a string pointer, to be returned by the function, with the signature.
 * If the msg_len is given to be 0, then msg is expected to be null terminated to find the size.
 * key bits lenght MUST be divisable by 8.
 *
 * free() must be called to free the returned string memory by the caller.
 */
uint_least8_t* _diode_SignString_wED25519PrivateBase64Key(const unsigned char* const IN msg, size_t msg_len,
                const unsigned char* const IN b64_key);

/* The functions verifies the given base64 encoded signature (sig) against the given message (msg) with the base64 encoded (public) key (b64_key).
 * All strings must be null terminated.
 * returns 1 on success, 0 on failure */
uint_fast8_t _diode_VerifySig_wED25519PublicBase64Key(const unsigned char* const IN sig, const unsigned char* const IN b64_key,
		const unsigned char* const IN msg);


/* The following functions return the size of McEliece's Public and Private Key size in b64 chars */
uint_least32_t _diode_mceliece460896f_PublicKeySizeInB64Chars(void);
uint_least32_t _diode_mceliece460896f_PrivateKeySizeInB64Chars(void);

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
int_fast8_t _diode_mceliece460896f_Keygen(uint_least8_t* const OUT prv_key, uint_least8_t* const OUT pub_key);





#endif /* _DIODE_KEYGEN_H */
