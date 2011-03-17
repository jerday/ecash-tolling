#ifndef SERVER_HPP
#define SERVER_HPP

#include <openssl/rsa.h>
#include <openssl/engine.h>

class Server {
public:
	static void key_generation();
	static void registration();
	static void sign();
	static RSA * rsa;
};

#endif
