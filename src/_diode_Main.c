#include <_diode_Main.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

#include <_diode_Encryption.h>
#include <_diode_Kem.h>
#include <_diode_Keygen.h>
#include <_diode_Sign.h>
#include <_diode_Utils.h>

int EMSCRIPTEN_KEEPALIVE _diode_Init()
{	
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	
	return 0;
}

int EMSCRIPTEN_KEEPALIVE _diode_Close()
{
	ENGINE_cleanup();
	CONF_modules_unload(1);
	EVP_cleanup();
	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
	CRYPTO_cleanup_all_ex_data();

	return 0;
}

int main(void)
{
	/*
	_diode_Init();
	unsigned char* msg = (unsigned char*) "Hello Wasm!";
	uint_least32_t pub_chars, prv_chars, out_chars, secret_chars, n_chars, e_chars, d_chars;
	unsigned char** prv_str = malloc(sizeof(*prv_str));
	unsigned char** pub_str = malloc(sizeof(*pub_str));
	unsigned char** rsa_n = malloc(sizeof(*rsa_n));
	unsigned char** rsa_e = malloc(sizeof(*rsa_e));
	unsigned char** rsa_d = malloc(sizeof(*rsa_d));
	//unsigned char** rsa_primes = malloc(sizeof(*rsa_primes));
	unsigned char** out_str = malloc(sizeof(*out_str));
	unsigned char** secret_str = malloc(sizeof(*secret_str));
	unsigned char** de_secret_str = malloc(sizeof(*de_secret_str));
	_diode_ED25519_Keygen(pub_str, &pub_chars, prv_str, &prv_chars);
	printf("PUB chars: %d | PRV chars: %d\n", pub_chars, prv_chars);
	printf("PUB ED25519 KEY: %s\n", *pub_str);
	printf("PRV ED25519 KEY: %s\n", *prv_str);
	uint_least8_t* dig = _diode_SignString_wED25519PrivateBase64Key(msg, 0, *prv_str);
	if(dig == NULL)
		return -1;
	printf("Digest: %s\n", dig);
	printf("Verify Success? : %d\n", _diode_VerifySig_wED25519PublicBase64Key(dig, *pub_str, msg));
	puts("Now RSA!");
	if(_diode_RSA_Keygen(rsa_n, &n_chars, rsa_e, &e_chars, rsa_d, &d_chars, NULL, NULL, 2048, 3, 73673))
	{
		return 1;
	}
	printf("PARAM N chars: %d | PARAM E chars: %d | PARAM D chars: %d\n", n_chars, e_chars, d_chars);
	printf("RSA N   PARAM: %s\n", *rsa_n);
	printf("RSA E   PARAM: %s\n", *rsa_e);
	printf("RSA D   PARAM: %s\n", *rsa_d);
	
	//printf("RSA P   PARAM: %s\n", rsa_primes[0]);
	//printf("RSA Q   PARAM: %s\n", rsa_primes[1]);
	//printf("RSA R_I PARAM: %s\n", rsa_primes[2]);
	
	puts("Now Encapsulation!");
	if(_diode_RSA_encapsulate(*rsa_n, 0, *rsa_e, 0, out_str, &out_chars, secret_str, &secret_chars))
	{
		return 1;
	}
	printf("OUT chars: %d | SECRET chars: %d\n", out_chars, secret_chars);
	printf("OUT   : %s\n", *out_str);
	printf("SECRET: %s\n", *secret_str);
	puts("Now Decapsulation!");
	if(_diode_RSA_decapsulate(*rsa_n, 0, *rsa_e, 0, *rsa_d, 0, *out_str, 0, de_secret_str, NULL))
	{
		return 1;
	}
	printf("SECRET: %s\n", *de_secret_str);
	puts("Now Encryption!");
	unsigned char* encrypt_data = (unsigned char*)"AQABff55AQABff55AQABff55";
	uint_least8_t** encrypt_str = malloc(sizeof(*encrypt_str));
	printf("ORIGINAL DATA: %s\n", encrypt_data);
	uint_least32_t data_size = 24;
	if(_diode_RSA_encrypt_wB64(*rsa_n, 0, *rsa_e, 0, encrypt_data, data_size, encrypt_str, NULL))
	{
		return 1;
	}
	printf("ENCRYPTED DATA: %s\n", *encrypt_str);
	puts("Now Decryption!");
	uint_least8_t** decrypted_data = malloc(sizeof(*decrypted_data));
	if(_diode_RSA_decrypt_wB64(*rsa_n, 0, *rsa_e, 0, *rsa_d, 0, *encrypt_str, 0, decrypted_data, NULL))
	{
		return 1;
	}
	printf("DECRYPTED DATA: %s\n", *decrypted_data);
	free(*decrypted_data);
	free(decrypted_data);
	free(*encrypt_str);
	free(encrypt_str);
	free(*rsa_n); free(*rsa_e); free(*rsa_d);
	free(rsa_n); free(rsa_e); free(rsa_d);
	free(*out_str);
	free(*secret_str);
	free(*de_secret_str);
	free(*prv_str);
	free(*pub_str);	
	puts("Now McEliece Key Generation");
	_diode_mceliece460896f_Keygen(pub_str, &pub_chars, prv_str, &prv_chars);
	printf("PUB chars: %d | PRV chars: %d\n", pub_chars, prv_chars);
	printf("PUB McEliece KEY: %s\n", *pub_str);
	printf("PRV McEliece KEY: %s\n", *prv_str);
	puts("Now McEliece Encapsulation");
	_diode_mceliece460896f_encapsulate(*pub_str, pub_chars, out_str, &out_chars, secret_str, &secret_chars);
	printf("OUT chars: %d | SECRET chars: %d\n", out_chars, secret_chars);
	printf("OUT   : %s\n", *out_str);
	printf("SECRET: %s\n", *secret_str);
	
	puts("Now McEliece Decapsulation");
	_diode_mceliece460896f_decapsulate(*prv_str, prv_chars, *out_str, out_chars, de_secret_str, NULL);
	printf("SECRET: %s\n", *de_secret_str);
	
	free(*de_secret_str);
	free(de_secret_str);
	free(*prv_str);
	free(*pub_str);
	free(prv_str);
	free(pub_str);
	free(*out_str);
	free(out_str);
	free(*secret_str);
	free(secret_str);
	_diode_Close();
	
	puts("main() is done!\n");
	
	*/
	return 0;
}
