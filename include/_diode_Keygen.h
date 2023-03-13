#ifndef _DIODE_KEYGEN_H
#define _DIODE_KEYGEN_H

#include <stdint.h>

/* Code Readability defines */
#define OUT
#define IN

#define _DIODE_DEBUG_LVL 2

#if defined(_DIODE_DEBUG_LVL) && _DIODE_DEBUG_LVL
        #if _DIODE_DEBUG_LVL == 1
        #define _DIODE_DEBUG_PRINT(x, args...) fprintf(stdout,(x) "\n", ##args)
        #elif _DIODE_DEBUG_LVL == 2
                #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
                #define _DIODE_DEBUG_PRINT(x, args...) fprintf(stdout, "DEBUG: %s:%d:%s(): " "\n"x, \
                __FILE__, __LINE__, __func__, ##args)
                #else
                #define _DIODE_DEBUG_PRINT(x, args...) fprintf(stdout, "DEBUG: %s:%d():" "\n" x, \
                __FILE__, __LINE__, ##args)
                #endif
        #else
        #error("Invalid _DIODE_DEBUG_LVL!!!")
        #endif /* _DIODE_DEBUG_LVL */
#else
#define _DIODE_DEBUG_PRINT(x, args...)
#endif


int _diode_Init();
int _diode_Close();

/* This function assumes there can't be an odd amount of nibbles representing a key,
 * returns base64 string size to represent the private key binary value, without the null terminator */
int_least32_t _diode_ED25519_Base64PrivateKeySize(void);

/* This function assumes there can't be an odd amount of nibbles representing a key,
 * returns base64 string size to represent the public key binary value, without the null terminator */
int_least32_t _diode_ED25519_Base64PublicKeySize(void);

/* This function converts the keys binary to base64 strings and copies them over to prvk for the private key and pubk for the public key.
 * It is the caller's responsibility to make sure the strings have enough space for the base64 strings + a null terminator
 * The space for these strings minus the null terminator can be found with _diode_ED25519_Base64PublicKeySize() and _diode_ED25519_Base64PrivateKeySize().
 * It is the CALLER'S RESPONSIBILITY to always free the memory of *all* pointers, or make sure they are freed.
 */
int _diode_ED25519_CopyKeys_Base64Str(unsigned char* const OUT prvk, unsigned char* const OUT pubk);

/* Generates a random pair of ED25519 Keys, deletes old ones if still in memory */
int _diode_ED25519_Keygen();


/* This functions expects the string to be null terminated and to be UTF8 / ASCCII.
 * This function also expects for the amount of chars from the base64 string to ALWAYS be a multiple of four.
 * Returs the amount of bytes needed to represent the base64 string in binary */
int_least32_t _diode_Base64StrSizeInBinaryBytes(const uint_least8_t* const IN str);

/* Convertes a base64 string (str) to its binary representation, writing it in mem.
 * It is the Caller's responsability to ensure mem has anough space for the binary,
 * to find this necessary size for a given b64 string, you can use _diode_Base64StrSizeInBinaryBytes() or _diode_Base64StrSizeInBinaryBytes_wStrSize()
 * str_size is needed if the string is not null terminated, if it is, str_size must be 0 . The str_size must be a multiple of four.
 * */
int  _diode_Base64Str_toBinary(const uint_least8_t* const IN str, uint_least8_t* const OUT mem, int_least32_t str_size);

/* Function writes the given binary data (mem) to str as a base64 sting
 * It is the caller's responsability to make sure str has enough space for the binary data in b64 format + a null terminator
 * To find the b64 str size without the null terminator use _DIODE_BASE64STR_SIZE_FROM_NBYTES */
void _diode_BinaryToBase64Str(const uint_least8_t* const IN mem, uint32_t size, uint_least8_t* const OUT str);


/* Generates a signature from a given string of a private key in base64 chars and a message,
 * Takes in the string (msg) to make the signature , private key string (b64_key),
 * and allocates a string pointer, to be returned by the function, with the signature.
 * If the msg_len is given to be 0, then msg is expected to be null terminated to find the size.
 * key bits lenght MUST be divisable by 8.
 *
 * free() must be called to free the returned string memory by the caller.
 */
uint_least8_t* _diode_SignString_wED25519PrivateBase64Key(const char* const IN msg, size_t msg_len,
                const char* const IN b64_key);

/* The functions verifies the given base64 encoded signature (sig) against the given message (msg) with the base64 encoded (public) key (b64_key).
 * All strings must be null terminated.
 * returns 1 on success, 0 on failure */
uint_fast8_t _diode_VerifySig_wED25519PublicBase64Key(const char* const IN sig, const char* const IN b64_key, const char* const IN msg);

#endif /* _DIODE_KEYGEN_H */
