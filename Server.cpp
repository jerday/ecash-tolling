#include "Server.hpp"
#include <iostream>
#include <string.h>
#include "stdlib.h"
#include <stdint.h>

using namespace std;

RSA * Server::rsa = NULL;
SHA256_CTX Server::sha256;
byte ** Server::spent_m;
int Server::spent_num;
BIO* Server::out = NULL;

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
    BN_mod_exp(gamma,c,rsa->d,rsa->n,bnCtx); // slowest

    //BIO_puts (out, "\nc = ");
    //BN_print (out, c);

    //BIO_puts (out, "\ngamma = ");
    //BN_print (out, gamma);

    //RSA_eay_mod_exp(gamma, c, rsa, bnCtx);  // better, requires copy paste function
    //BN_MONT_CTX * montCtx = BN_MONT_CTX_new();
    //BN_mod_exp_mont(gamma,c,rsa->d,rsa->n,bnCtx,montCtx);
    return gamma;
}

void Server::registration() {
    spent_m = new byte*[24 * 60];
    for (int i = 0; i < 24 * 60; ++i) {
        spent_m[i] = new byte [64];
    }
    spent_num = 0;

    out = BIO_new_file ("server_debug.log", "w");

    if (out == NULL) {
        printf ("debug file failed to establish\n");
        exit (-1);
    } else {
        printf ("debug file established\n");
    }

}

BIGNUM * Server::get_n() {
    return rsa->n;
}

BIGNUM * Server::get_e() {
    return rsa->e;
}

//for debug
BIGNUM * Server::get_d() {
    return rsa->d;
}

bool used (byte * _m1, byte * _m2) {
    for (int i = 0; i < 64; ++i) {
    //    printf ("_m1[%d] = %d , _m2[%d] = %d \n", i, _m1[i], i, _m2[i]);
        if (_m1[i] != _m2[i])
            return false;
    }
    return true;
}


bool Server::verify_token (byte * h, int *t, BIGNUM * s, BIGNUM * sigma) {

//    printf ("Server::verifying token\n");

    //now it is a naive solution, we simply use an array
    byte* _m = new byte [64];
    memcpy (_m, h, 32);


//    printf ("Server::verifying token1\n");
    //compute m = (h, H(t,s))
    byte ts[20]; // 4 + 16
    memcpy(ts,t, 4);
    memcpy(ts+4,s,16);

    SHA256_Init(&sha256);
    SHA256_Update(&sha256,ts,20);
    SHA256_Final(_m + 32,&sha256); // _m[i] = (H(i,r),H(t,s))


//    printf ("Server::verifying token2\n");

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
//    printf ("Server::verifying token3\n");
    spent_m[spent_num++] = _m;
//    printf ("Server: new token\n");

//    printf ("Server::verifying token4\n");
    //check signature: H(m) = sigma^e
    byte H_m[33];
    SHA256_Init(&sha256);
    SHA256_Update(&sha256,_m,64);
    SHA256_Final(H_m,&sha256);

    byte H_mi[128];


    for (int k = 0; k < 4; k++) {
        H_m[32] = k;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256,H_m,33);
        SHA256_Final(H_mi+32*k,&sha256);
    }

//    printf ("Server::verifying token5\n");
    BN_CTX * bnCtx = BN_CTX_new();
    BIGNUM *sigma_pow_e = BN_new();
    BN_mod_exp(sigma_pow_e,sigma,Server::get_e(),Server::get_n(),bnCtx);

    BIGNUM * bn_H_m = BN_new();
    BN_bin2bn(H_mi,128,bn_H_m);
    BN_nnmod(bn_H_m,bn_H_m,Server::get_n(),bnCtx);
//    printf ("Server::verifying token6\n");

    if (BN_cmp (sigma_pow_e, bn_H_m) == 0) {
        //valid signature
        return true;
    } else {
        //invalid signature
        printf ("Server: Invalid signature\n");

        printf ("Server::ts = \n");

        for (int j = 0; j < 20; ++j) {
            printf ("%d", ts[j]);
        }
        printf ("\n");
        //output m = (H(i,r), H(t,s));
        //DEBUG
        BIGNUM * bn_m= BN_new();
        BN_bin2bn(_m,64,bn_m);
        BIO_puts (out, "\nm = ");
        BN_print (out, bn_m);

        //output h(m)
        //DEBUG
        BIO_puts (out, "\nbn_H_m = ");
        BN_print (out, bn_H_m);

        //output H(m)^e
        //DEBUG
        BIO_puts (out, "\nH(m)^e=");
        BN_print (out, sigma_pow_e);

        //output sigma
        //DEBUG
        BIO_puts (out, "\nsigma=");
        BN_print (out, sigma);

        return false;
    }
//    printf ("Server::verifying token3\n");
}
