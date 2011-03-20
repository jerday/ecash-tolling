#include "Client.hpp"
#include "Server.hpp"

#include "stdlib.h"
#include <string.h>
#include <iostream>
#include <time.h>
#include <omp.h>

double tstart, tstop, ttime;

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
	_t = new int*[num_times];
	_r = new BIGNUM*[num_tags];
	_s = new BIGNUM*[num_tags];
	_sigma = new BIGNUM*[num_tags];

	for(int i = 0; i < num_tags; i++) {
		_m[i] = new byte[64];
		_r[i] = BN_new();
		_s[i] = BN_new();
		_sigma[i] = BN_new();
		BN_rand(_r[i],128,-1,-1);
		BN_rand(_s[i],128,-1,-1);
	}

	for(int i = 0; i < num_times; i++) {
		_t[i] = new int(i);
	}

	// _i = (some unique identity);
	RAND_bytes(_i,32);

	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	double start = omp_get_wtime( );
int tid, nthreads, chunk;
chunk = 10;
int i = 0;

	#pragma omp parallel default(shared) private(i) \
		num_threads(32)
	{
		tid = omp_get_thread_num();
		if (tid == 0)
		{
			nthreads = omp_get_num_threads();
			printf("Number of threads = %d\n", nthreads);
		}
		printf("Thread %d starting...\n",tid);
	#pragma omp for schedule(static)
	for(i = 0; i < num_tags; i++) {
		// For each ticket i, the user sets m = (H(i,r),H(t,s)) where r and
		// s are random salts.
//		printf ("Thread %d: current i = %d\n", tid, i);

		BN_CTX * bnCtx = BN_CTX_new();

		byte ir[48];
		memcpy(ir,_i,32);
		memcpy(ir+32,_r[i],16);
		SHA256_Update(&sha256,ir,48);
		SHA256_Final(_m[i],&sha256); // m = H(i,r)
		byte ts[18]; // 2 + 16
		memcpy(ts,_t[i%num_times],2);
		memcpy(ts+2,_s[i],16);
		SHA256_Update(&sha256,ts,48);
		SHA256_Final(_m[i]+32,&sha256); // _m[i] = (H(i,r),H(t,s))

//		printf ("Thread %d HERE1: current i = %d\n", tid, i);
		//  The value c = x^e H(m) is sent to the server
		byte H_m[32];
		SHA256_Update(&sha256,_m[i],64);
		SHA256_Final(H_m,&sha256);

		BIGNUM * x = BN_new();
		BN_rand_range(x,Server::get_n()); // generate random x less than n
		// raise x^e

		BIGNUM * x_pow_e = BN_new();
		BN_mod_exp(x_pow_e,x,Server::get_e(),Server::get_n(),bnCtx);
//		printf ("Thread %d HERE2: current i = %d\n", tid, i);

		BIGNUM * bn_H_m = BN_new();
		BN_bin2bn(H_m,32,bn_H_m);

		BIGNUM * c = BN_new();
		BN_mod_mul(c,bn_H_m,x_pow_e,Server::get_n(),bnCtx);

		BIGNUM * gamma = Server::compute_gamma(c,bnCtx);
		BN_div(_sigma[i],NULL,gamma,x,bnCtx);
	}
	}

double end = omp_get_wtime( );

printf ("time spent in phase 2: %.16g\n", end - start); 
}

void Client::reveal() {

}

void Client::payment() {

}
