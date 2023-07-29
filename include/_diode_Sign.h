#ifndef _DIODE_SIGN_H
#define _DIODE_SIGN_H

#include <stdint.h>
#include <emscripten.h>

/* Signs the given message with a private key in base64,
 * Takes in the message string (msg) to make the digest (dig), signing with private key string (prv_key_str),
 * and allocates a string stored in *dig, with the digest.
 * If the msg_len/prv_key_chars is given to be 0, then msg/prv_key_str is expected to be null terminated to find the size.
 *
 * free() must be called to free the returned string memory by the caller.
 * 
 * error codes:
 * -1  msg, prv_key_str or dig was given as a NULL pointer.
 * -2  Invalid private key given.
 * -3  Couldn't allocate private key memory.
 * -4  Couldn't convert private key to binary.
 * -5  Couldn't create EVP_PKEY object.
 * -6  Couldn't create EVP_MD_CTX object.
 * -7  Couldn't initialize CTX.
 * -8  Couldn't get digest size.
 * -9  Couldn't allocate digest memory.
 * -10 Couldn't sign.
 * -11 Couldn't allocate memory for digest string.
 * -12 Couldn't convert signature binary to b64 string.
 */
extern int_fast8_t EMSCRIPTEN_KEEPALIVE _diode_SignString_wED25519PrivateBase64Key(const unsigned char* const IN msg, size_t msg_len,
		const unsigned char* const IN prv_key_str, uint_least32_t prv_key_chars,
		uint_least8_t** OUT dig);

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

#endif /* _DIODE_SIGN_H */
