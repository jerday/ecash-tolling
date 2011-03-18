#include "Client.hpp"
#include "Server.hpp"

#include <string.h>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/sha.h>

Client::Client() {
}

Client::~Client() {
}

/**
 * Client registration.
 *
 * revealed_per_interval: the rate that tickets revealed per minute (e.g. 0.5 or 1)
 * tags_each_reveal: the number of tickets revealed each time reveal is
 *						  called, which is reveal_rate / minute.
 * period_length: the length in days of a period (e.g. 30)
 */
void Client::registration(double revealed_per_interval, int tags_each_reveal, int period_length) {
	// The number of time intervals in a period.
	int num_times = (int) (revealed_per_interval * 60 * 24 * period_length);
	int num_tags = num_times * tags_each_reveal;

	// Initialize all tag data
	_m = new byte*[num_tags];
	_t = new byte*[num_tags];
	_r = new byte*[num_tags];
	_s = new byte*[num_tags];
	_sigma = new byte*[num_tags];
	for(int i = 0; i < num_tags; i++) {
		_m[i] = new byte[64];
		_t[i] = new byte[2];  // not sure about size here
		_r[i] = new byte[16]; // 128 bit salt
		_s[i] = new byte[16]; // 128 bit salt
		RAND_bytes(_r[i],16);
		RAND_bytes(_s[i],16);
		// [TODO]: initialize _t for each i
	}

	// _i = (some unique identity);
	RAND_bytes(_i,32);

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	BN_CTX * bnCtx = BN_CTX_new();
	for(int i = 0; i < num_tags; i++) {
		// For each ticket i, the user sets m = (H(i,r),H(t,s)) where r and
		// s are random salts.
		byte ir[48];
		memcpy(ir,_i,32);
		memcpy(ir+32,_r[i],16);
		SHA256_Update(&sha256,ir,48);
		SHA256_Final(_m[i],&sha256); // m = H(i,r)
		byte ts[18]; // 2 + 16
		memcpy(ts,_t[i],2);
		memcpy(ts+2,_s[i],16);
		SHA256_Update(&sha256,ts,48);
		SHA256_Final(_m[i]+32,&sha256); // _m[i] = (H(i,r),H(t,s))

		//  The value c = x^e H(m) is sent to the server
		byte H_m[32];
		SHA256_Update(&sha256,_m[i],64);
		SHA256_Final(H_m,&sha256);

		BIGNUM * x = BN_new();
		BN_rand_range(x,Server::rsa->n); // generate random x less than n
		// raise x^e

		BIGNUM * x_pow_e = BN_new();
		BN_mod_exp(x_pow_e,x,Server::rsa->e,Server::rsa->n,bnCtx);

		BIGNUM * bn_H_m = BN_new();
		BN_bin2bn(H_m,32,bn_H_m);
		BIGNUM * c = BN_new();
		BN_mod_mul(c,bn_H_m,x_pow_e,Server::rsa->n,bnCtx);
	}
}

void Client::reveal() {

}

void Client::payment() {

}
