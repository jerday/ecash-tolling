#ifndef SERVER_HPP
#define SERVER_HPP

#include <openssl/rsa.h>
#include <openssl/engine.h>

class Server {
public:
	static void key_generation();
	static void registration();
	static bool verify_token(byte * h, int t, BIGNUM * s, BIGNUM * sigma);
	static BIGNUM * compute_gamma(BIGNUM * c,BN_CTX * bnCtx);
	static BIGNUM * get_n();
	static BIGNUM * get_e();
private:
	static RSA * rsa;
	static SHA256_CTX sha256;

	static byte ** spent_m;
	int spent_num;
};

#endif
