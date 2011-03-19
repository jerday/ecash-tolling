#ifndef SERVER_HPP
#define SERVER_HPP

#include <openssl/rsa.h>
#include <openssl/engine.h>

class Server {
public:
	static void key_generation();
	static void registration();
	static void sign();
	static BIGNUM * compute_gamma(BIGNUM * c,BN_CTX * bnCtx);
	static BIGNUM * get_n();
	static BIGNUM * get_e();
private:
	static RSA * rsa;
};

#endif
