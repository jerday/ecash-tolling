#include "Server.hpp"
#include <iostream>

RSA * Server::rsa = NULL;

void Server::key_generation() {
	// Server selects an RSA modulus N = pq and determines e, d such
	// that ed ≡ 1 (mod phi(N)). The public key is (e,N), the private
	// key is (d,p,q).
	rsa = RSA_generate_key(1092/*3072 - slow */,RSA_F4,NULL,NULL);
	std::cout << "Key generation complete.";
}

void Server::registration() {
}

void Server::sign() {
	// Compute blinded signature and return it.
}
