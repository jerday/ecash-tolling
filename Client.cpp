#include "Client.hpp"
#include "Server.hpp"

#include "stdlib.h"
#include <string.h>
#include <iostream>
#include <time.h>
#include <omp.h>
#include <openssl/bio.h>

using namespace std;

double tstart, tstop, ttime;

Client::Client() {
	out = BIO_new_file ("client_debug.log", "w");
	if (out == NULL) {
		printf ("debug file failed to establish\n");
		exit (-1);
	} else {
		printf ("debug file established\n");
	}

	//BIO_set_fp(out,stdout,BIO_NOCLOSE);
	//the line above is to redirect the output stream to the screen
}

Client::~Client() {
	BIO_free (out);
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
	num_tags = num_times * tags_each_reveal;
	
	//debug 
	num_tags = 1;

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
		_t[i] = new int(1); //new int(i);
	}

	// _i = (some unique identity);
	RAND_bytes(_i,32);


	double start = omp_get_wtime( );
	int tid, nthreads, chunk;
	chunk = 10;
	int i = 0;
	SHA256_CTX sha256;

	#pragma omp parallel default(shared) private(i) \
		num_threads(1)
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

			SHA256_Init(&sha256);
			SHA256_Update(&sha256,ir,48);
			SHA256_Final(_m[i],&sha256); // m = H(i,r)
			
			//output m = H(i,r);
			//DEBUG
			BIGNUM * bn_H_i_r= BN_new();
			BN_bin2bn(_m[i],32,bn_H_i_r);
			BIO_puts (out, "\nH(i,r) = ");
			BN_print (out, bn_H_i_r); 


			byte ts[20]; // 4 + 16
			memcpy(ts,_t[i%num_times],4);
			memcpy(ts+4,_s[i],16);
			//SHA256_Update(&sha256,ts,0);
			SHA256_Init(&sha256);
			SHA256_Update(&sha256,ts,20);
			SHA256_Final(_m[i]+32,&sha256); // _m[i] = (H(i,r),H(t,s))
			//SHA256_Final(_m[i],&sha256); // _m[i] = (H(i,r),H(t,s))

			printf ("Client::ts = \n");
			for (int j = 0; j < 20; ++j)
				printf ("%d", ts[j]);
			printf ("\n");


			//output m = (H(i,r), H(t,s));
			//DEBUG
			BIGNUM* bn_m= BN_new();
			BN_bin2bn(_m[i],64,bn_m);
			BIO_puts (out, "\n(H(i,r), H(t,s) = ");
			BN_print (out, bn_m); 


	//		printf ("Thread %d HERE1: current i = %d\n", tid, i);
			//  The value c = x^e H(m) is sent to the server
			byte H_m[32];
			SHA256_Init(&sha256);
			SHA256_Update(&sha256,_m[i],64);
			SHA256_Final(H_m,&sha256);



			BIGNUM * x = BN_new();
			BN_rand_range(x,Server::get_n()); // generate random x less than n
			// raise x^e

			BIO_puts (out, "\nx = ");
			BN_print (out, x); 

			BIGNUM * x_pow_e = BN_new();
			BN_mod_exp(x_pow_e,x,Server::get_e(),Server::get_n(),bnCtx);
	//		printf ("Thread %d HERE2: current i = %d\n", tid, i);

			//output x^e
			//DEBUG
			BIO_puts (out, "\nx ^ e = ");
			BN_print (out, x_pow_e); 



			BIGNUM * bn_H_m = BN_new();
			BN_bin2bn(H_m,32,bn_H_m);


			//output h(m)
			//DEBUG
			BIO_puts (out, "\nh(m) = ");
			BN_print (out, bn_H_m); 


			BIGNUM * c = BN_new();
			BN_mod_mul(c,bn_H_m,x_pow_e,Server::get_n(),bnCtx);

			//output x^e
			//DEBUG
			BIO_puts (out, "\nc = ");
			BN_print (out, c); 


			BIGNUM * gamma = Server::compute_gamma(c,bnCtx);
			BN_div(_sigma[i],NULL,gamma,x,bnCtx);


			//output gamma
			//DEBUG
			BIO_puts (out, "\ngamma = ");
			BN_print (out, gamma); 

			//output sigma
			//DEBUG
			BIO_puts (out, "\nsigma = ");
			BN_print (out, _sigma[i]); 
		}
	}
	double end = omp_get_wtime( );
	printf ("time spent in phase 2: %.16g\n", end - start);
}

void Client::reveal(float percentage) {
	int tokens_spent = num_tags * percentage;
	//for debug
	tokens_spent = 1;
	printf ("Client::revealing a percentage of %.2g tickets \n", percentage);
	int i;
	for (i = 0; i < tokens_spent; ++i) {
		//now spend all the tokens
		if (Server::verify_token (_m[i], _t[0], _s[i], _sigma[i])) {
			printf ("token# %d verified\n", i);
		} else {
			printf ("token# %d not verified\n", i);
		}
	}
}

void Client::payment() {
}
