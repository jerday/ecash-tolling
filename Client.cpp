#include "Client.hpp"
#include "Server.hpp"

#include "stdlib.h"
#include <string.h>
#include <iostream>
#include <time.h>
#include <omp.h>
#include "openssl/bio.h"

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
    cc_bytes = 0;

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
 *                          called, which is reveal_rate / minute.
 * period_length: the length in days of a period (e.g. 30)
 */
void Client::registration(double revealed_per_interval, int tags_each_reveal, int period_length) {
    // The number of time intervals in a period.

    int num_times = (int) (revealed_per_interval * 60 * 24 * period_length);
    num_tags = num_times * tags_each_reveal;
    printf ("number of tags in total = %d\n", num_tags);
    printf ("number of times = %d\n", num_times);
  //  num_tags = 1;

    //debug
   //num_tags = 3;

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
    int nthreads, chunk;
    chunk = 10;
    int i = 0;


    #pragma omp parallel default(shared) private(i) \
        num_threads(1)
    {
        int tid = omp_get_thread_num();
        if (tid == 0)
        {
            nthreads = omp_get_num_threads();
            printf("Number of threads = %d\n", nthreads);
        }
    //    printf("Thread %d starting...\n",tid);
        SHA256_CTX sha256;
        BN_CTX * bnCtx = BN_CTX_new();

        #pragma omp for schedule(static)
        for(i = 0; i < num_tags; i++) {
            // For each ticket i, the user sets m = (H(i,r),H(t,s)) where r and
            // s are random salts.
    //        printf ("Thread %d: current i = %d\n", tid, i);

            byte ir[48];
            memcpy(ir,_i,32);
            memcpy(ir+32,_r[i],16);

            SHA256_Init(&sha256);
            SHA256_Update(&sha256,ir,48);
            SHA256_Final(_m[i],&sha256); // m = H(i,r)

            byte ts[20]; // 4 + 16
            memcpy(ts,_t[i%num_times],4);
            memcpy(ts+4,_s[i],16);
            SHA256_Init(&sha256);
            SHA256_Update(&sha256,ts,20);
            SHA256_Final(_m[i]+32,&sha256); // _m[i] = (H(i,r),H(t,s))

            //  The value c = x^e H(m) is sent to the server
            byte H_m[33];
            SHA256_Init(&sha256);
            SHA256_Update(&sha256,_m[i],64);
            SHA256_Final(H_m,&sha256);

            byte H_mi[128];

            for (int k = 0; k < 4; k++) {
                H_m[32] = k;
                SHA256_Init(&sha256);
                SHA256_Update(&sha256,H_m,33);
                SHA256_Final(H_mi+32*k,&sha256);
            }

            BIGNUM * x = BN_new();
            BN_rand_range(x,Server::get_n()); // generate random x less than n
            // raise x^e

            BIGNUM * x_pow_e = BN_new();
            BN_mod_exp(x_pow_e,x,Server::get_e(),Server::get_n(),bnCtx);

            //output x^e
            //DEBUG
        //    BIO_puts (out, "\nx ^ e = ");
        //    BN_print (out, x_pow_e);

            BIGNUM * bn_H_m = BN_new();
            BN_bin2bn(H_mi,128,bn_H_m);
            BN_nnmod(bn_H_m,bn_H_m,Server::get_n(),bnCtx);

            //output h(m)
            //DEBUG
            BIO_puts (out, "\nbn_H_m = ");
            BN_print (out, bn_H_m);

            BIGNUM * c = BN_new();
            BN_mod_mul(c,bn_H_m,x_pow_e,Server::get_n(),bnCtx);

            //output x^e
            //DEBUG
            //BIO_puts (out, "\nc = ");
            //BN_print (out, c);


    //	printf ("Thread %d HERE4: current i = %d\n", tid, i);
	    cc_bytes += 1024 / 8;
            BIGNUM * gamma = Server::compute_gamma(c,bnCtx);
	    cc_bytes += 1024 / 8;
            BIGNUM * x_inverse = BN_new();
            BN_mod_inverse(x_inverse, x, Server::get_n(), bnCtx);
            BN_mod_mul(_sigma[i], x_inverse, gamma, Server::get_n(), bnCtx);


    //	printf ("Thread %d HERE5: current i = %d\n", tid, i);
            //output c^d
        //    BIGNUM * c_pow_d = BN_new();
        //    BN_mod_exp(c_pow_d,c,Server::get_d(),Server::get_n(),bnCtx);
        //    BIO_puts (out, "\nc^d = ");
        //    BN_print (out, c_pow_d);


        }
    }
    double end = omp_get_wtime( );
    printf ("registration takes %.16g seconds\n", end - start);
}

void Client::reveal(float percentage) {
    double start = omp_get_wtime( );
    int tokens_spent = num_tags * percentage;
    //for debug
    printf ("Client::revealing %.2g%% tickets \n", percentage * 100);
    int i;

    /*test of spending*/
    for (i = 0; i < tokens_spent; ++i) {
        //now spend all the tokens
	    cc_bytes += 1024 / 8;
        if (Server::verify_token (_m[i], _t[0], _s[i], _sigma[i])) {
//            printf ("token# %d verified\n", i);
        } else {
            printf ("token# %d not verified\n", i);

            //output m = H(i,r);
            //DEBUG
            BIGNUM * bn_H_i_r= BN_new();
            BN_bin2bn(_m[i],32,bn_H_i_r);
            BIO_puts (out, "\nH(i,r) = ");
            BN_print (out, bn_H_i_r);

            //output m = (H(i,r), H(t,s));
            //DEBUG
            BIGNUM* bn_m= BN_new();
            BN_bin2bn(_m[i],64,bn_m);
            BIO_puts (out, "\n(H(i,r), H(t,s) = ");
            BN_print (out, bn_m);

            //output sigma
            //DEBUG
            BIO_puts (out, "\nsigma = ");
            BN_print (out, _sigma[i]);

            printf ("\n");

        }
	}

        /*test of collision*/
    /*
   	printf ("Now it's a test of collision\n");
	tokens_spent = 2;
	for (int i = 0; i < tokens_spent; ++i) {
        	if (Server::verify_token (_m[0], _t[0], _s[0], _sigma[0])) {
       		     printf ("token# %d verified\n", i);
       		 } else {
       		     printf ("token# %d not verified\n", i);
       		 }
	}
	*/
    double end = omp_get_wtime( );
    printf ("revealing takes %.16g seconds\n", end - start);
}

void Client::payment() {
	Server::payment();
}
