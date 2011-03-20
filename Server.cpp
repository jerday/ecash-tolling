#include "Server.hpp"
#include <iostream>
#include <string.h>
#include "stdlib.h"
using namespace std;

RSA * Server::rsa = NULL;
SHA256_CTX Server::sha256;
byte ** Server::spent_m;
int Server::spent_num;

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
	//RSA_eay_mod_exp(gamma, c, rsa, bnCtx);  // better, requires copy paste function
	BN_MONT_CTX * montCtx = BN_MONT_CTX_new();
	BN_mod_exp_mont(gamma,c,rsa->d,rsa->n,bnCtx,montCtx);
	return gamma;
}

void Server::registration() {
	spent_m = new byte*[24 * 60];
	for (int i = 0; i < 24 * 60; ++i) {
		spent_m[i] = new byte [64];
	}
	SHA256_Init(&sha256);
	spent_num = 0;
}

BIGNUM * Server::get_n() {
	return rsa->n;
}

BIGNUM * Server::get_e() {
	return rsa->e;
}

bool used (byte * _m1, byte * _m2) {
	for (int i = 0; i < 64; ++i) {
		if (_m1[i] != _m2[i])
			return false;
	}
}


bool Server::verify_token (byte * h, int *t, BIGNUM * s, BIGNUM * sigma) {

	printf ("Server::verifying token\n");

	//now it is a naive solution, we simply use an array
	byte* _m = new byte [64];
	memcpy (_m, h, 32);

	printf ("Server::verifying token1\n");
	//compute m = (h, H(t,s))
	byte ts[20]; // 4 + 16
	memcpy(ts,t, 4);
	memcpy(ts+4,s,16);
	SHA256_Update(&sha256,ts,48);
	SHA256_Final(_m+32,&sha256); // _m[i] = (H(i,r),H(t,s))

	printf ("Server::verifying token2\n");
	//verifies that t is correct
	if (*t != 1) {
		printf ("Server: t not correct, should be 1, but now is %d\n", *t);
	}

	//verifies that m has not been used
	for (int i = 0; i < spent_num; ++i) {
		if (used(_m, spent_m[i])) {
			printf ("Server: This ticket has been used\n");
			return false;
		}
	}
	printf ("Server::verifying token3\n");
	spent_m[spent_num++] = _m;
	printf ("Server: new token\n");

	printf ("Server::verifying token4\n");
	//check signature: H(m) = sigma^e
	byte H_m[32];
	SHA256_Update(&sha256,_m,64);
	SHA256_Final(H_m,&sha256);

	printf ("Server::verifying token5\n");
	BN_CTX * bnCtx = BN_CTX_new();
	BIGNUM *sigma_pow_e = BN_new();
	BN_mod_exp(sigma_pow_e,sigma,Server::get_e(),Server::get_n(),bnCtx);

	BIGNUM * bn_H_m = BN_new();
	BN_bin2bn(H_m,32,bn_H_m);
	printf ("Server::verifying token6\n");

	if (BN_cmp (sigma_pow_e, bn_H_m) == 0) {
		//valid signature
		return true;
	} else {
		//invalid signature
		printf ("Server: Invalid signature\n");
		return false;
	}
	printf ("Server::verifying token3\n");
}
