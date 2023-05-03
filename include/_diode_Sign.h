#ifndef _DIODE_SIGN_H
#define _DIODE_SIGN_H

#include <stdint.h>
#include <emscripten.h>

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

#endif /* _DIODE_SIGN_H */
