#include "Server.hpp"
#include <iostream>

RSA * Server::rsa = NULL;

void Server::key_generation() {
	// Server selects an RSA modulus N = pq and determines e, d such
	// that ed ≡ 1 (mod phi(N)). The public key is (e,N), the private
	// key is (d,p,q).
	//rsa = RSA_generate_key(1092/*3072 - slow */,RSA_F4,NULL,NULL);
	rsa = RSA_generate_key(1024/*3072 - slow */,RSA_F4,NULL,NULL);
	std::cout << "Key generation complete." << std::endl;
}

BIGNUM * Server::compute_gamma(BIGNUM * c,BN_CTX * bnCtx) {
	BIGNUM * gamma = BN_new();
	//BN_mod_exp(gamma,c,rsa->d,rsa->n,bnCtx); // slowest
	///RSA_eay_mod_exp(gamma, c, rsa, bnCtx);  // better, requires copy paste function
	BN_MONT_CTX * montCtx = BN_MONT_CTX_new();
	BN_mod_exp_mont(gamma,c,rsa->d,rsa->n,bnCtx,montCtx);
	return gamma;
}

void Server::registration() {
}

BIGNUM * Server::get_n() {
	return rsa->n;
}

BIGNUM * Server::get_e() {
	return rsa->e;
}

