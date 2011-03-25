#include "Server.hpp"
#include <iostream>
#include <string.h>
#include "stdlib.h"
#include <stdint.h>

using namespace std;

RSA * Server::rsa = NULL;
SHA256_CTX Server::sha256;
int * Server::spent_m;
int Server::spent_num;
BIO* Server::out = NULL;

static int RSA_eay_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
	{
	BIGNUM *r1,*m1,*vrfy;
	BIGNUM local_dmp1,local_dmq1,local_c,local_r1;
	BIGNUM *dmp1,*dmq1,*c,*pr1;
	int ret=0;

	BN_CTX_start(ctx);
	r1 = BN_CTX_get(ctx);
	m1 = BN_CTX_get(ctx);
	vrfy = BN_CTX_get(ctx);

	{
		BIGNUM local_p, local_q;
		BIGNUM *p = NULL, *q = NULL;

		/* Make sure BN_mod_inverse in Montgomery intialization uses the
		 * BN_FLG_CONSTTIME flag (unless RSA_FLAG_NO_CONSTTIME is set)
		 */
		if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
			{
			BN_init(&local_p);
			p = &local_p;
			BN_with_flags(p, rsa->p, BN_FLG_CONSTTIME);

			BN_init(&local_q);
			q = &local_q;
			BN_with_flags(q, rsa->q, BN_FLG_CONSTTIME);
			}
		else
			{
			p = rsa->p;
			q = rsa->q;
			}

		if (rsa->flags & RSA_FLAG_CACHE_PRIVATE)
			{
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_p, CRYPTO_LOCK_RSA, p, ctx))
				goto err;
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_q, CRYPTO_LOCK_RSA, q, ctx))
				goto err;
			}
	}

	if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
		if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n, CRYPTO_LOCK_RSA, rsa->n, ctx))
			goto err;

	/* compute I mod q */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		c = &local_c;
		BN_with_flags(c, I, BN_FLG_CONSTTIME);
		if (!BN_mod(r1,c,rsa->q,ctx)) goto err;
		}
	else
		{
		if (!BN_mod(r1,I,rsa->q,ctx)) goto err;
		}

	/* compute r1^dmq1 mod q */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		dmq1 = &local_dmq1;
		BN_with_flags(dmq1, rsa->dmq1, BN_FLG_CONSTTIME);
		}
	else
		dmq1 = rsa->dmq1;
	if (!rsa->meth->bn_mod_exp(m1,r1,dmq1,rsa->q,ctx,
		rsa->_method_mod_q)) goto err;

	/* compute I mod p */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		c = &local_c;
		BN_with_flags(c, I, BN_FLG_CONSTTIME);
		if (!BN_mod(r1,c,rsa->p,ctx)) goto err;
		}
	else
		{
		if (!BN_mod(r1,I,rsa->p,ctx)) goto err;
		}

	/* compute r1^dmp1 mod p */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		dmp1 = &local_dmp1;
		BN_with_flags(dmp1, rsa->dmp1, BN_FLG_CONSTTIME);
		}
	else
		dmp1 = rsa->dmp1;
	if (!rsa->meth->bn_mod_exp(r0,r1,dmp1,rsa->p,ctx,
		rsa->_method_mod_p)) goto err;

	if (!BN_sub(r0,r0,m1)) goto err;
	/* This will help stop the size of r0 increasing, which does
	 * affect the multiply if it optimised for a power of 2 size */
	if (BN_is_negative(r0))
		if (!BN_add(r0,r0,rsa->p)) goto err;

	if (!BN_mul(r1,r0,rsa->iqmp,ctx)) goto err;

	/* Turn BN_FLG_CONSTTIME flag on before division operation */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		pr1 = &local_r1;
		BN_with_flags(pr1, r1, BN_FLG_CONSTTIME);
		}
	else
		pr1 = r1;
	if (!BN_mod(r0,pr1,rsa->p,ctx)) goto err;

	/* If p < q it is occasionally possible for the correction of
         * adding 'p' if r0 is negative above to leave the result still
	 * negative. This can break the private key operations: the following
	 * second correction should *always* correct this rare occurrence.
	 * This will *never* happen with OpenSSL generated keys because
         * they ensure p > q [steve]
         */
	if (BN_is_negative(r0))
		if (!BN_add(r0,r0,rsa->p)) goto err;
	if (!BN_mul(r1,r0,rsa->q,ctx)) goto err;
	if (!BN_add(r0,r1,m1)) goto err;

	if (rsa->e && rsa->n)
		{
		if (!rsa->meth->bn_mod_exp(vrfy,r0,rsa->e,rsa->n,ctx,rsa->_method_mod_n)) goto err;
		/* If 'I' was greater than (or equal to) rsa->n, the operation
		 * will be equivalent to using 'I mod n'. However, the result of
		 * the verify will *always* be less than 'n' so we don't check
		 * for absolute equality, just congruency. */
		if (!BN_sub(vrfy, vrfy, I)) goto err;
		if (!BN_mod(vrfy, vrfy, rsa->n, ctx)) goto err;
		if (BN_is_negative(vrfy))
			if (!BN_add(vrfy, vrfy, rsa->n)) goto err;
		if (!BN_is_zero(vrfy))
			{
			/* 'I' and 'vrfy' aren't congruent mod n. Don't leak
			 * miscalculated CRT output, just do a raw (slower)
			 * mod_exp and return that instead. */

			BIGNUM local_d;
			BIGNUM *d = NULL;
		
			if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
				{
				d = &local_d;
				BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
				}
			else
				d = rsa->d;
			if (!rsa->meth->bn_mod_exp(r0,I,d,rsa->n,ctx,
						   rsa->_method_mod_n)) goto err;
			}
		}
	ret=1;
err:
	BN_CTX_end(ctx);
	return(ret);
	}


int byte_to_int (byte* H_mi) {
	int ans = 0;
	for (int i = 0; i < 4; ++i) {
		ans = (ans << 8) + H_mi[i];
	}
	return ans;
}

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
//    BN_mod_exp(gamma,c,rsa->d,rsa->n,bnCtx); // slowest

    //BIO_puts (out, "\nc = ");
    //BN_print (out, c);

    //BIO_puts (out, "\ngamma = ");
    //BN_print (out, gamma);

//<<<<<<< HEAD
	RSA_eay_mod_exp(gamma, c, rsa, bnCtx);  // better, requires copy paste function
//	BN_MONT_CTX * montCtx = BN_MONT_CTX_new();
//	BN_mod_exp_mont(gamma,c,rsa->d,rsa->n,bnCtx,montCtx);
	return gamma;
//=======
    //RSA_eay_mod_exp(gamma, c, rsa, bnCtx);  // better, requires copy paste function
    //BN_MONT_CTX * montCtx = BN_MONT_CTX_new();
    //BN_mod_exp_mont(gamma,c,rsa->d,rsa->n,bnCtx,montCtx);
 //   return gamma;
}

void Server::registration() {
    //spent_m = new byte*[24 * 60];
	spent_m = new int [24 * 60 * 200];
	/*
    for (int i = 0; i < 24 * 60; ++i) {
        spent_m[i] = new byte [64];
    }
    */
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


/*
    //verifies that m has not been used
    for (int i = 0; i < spent_num; ++i) {
        if (used(_m, spent_m[i])) {
            printf ("Server: This ticket has been used\n");
            return false;
        }
    }
    spent_m[spent_num++] = _m;
    */

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

    int h_m_int = byte_to_int (H_mi);
    //printf ("h_m_int = %d\n", h_m_int);
    for (int i = 0; i < spent_num; ++i) {
        //if (used(_m, spent_m[i])) {
	if (h_m_int == spent_m[i]) {
            printf ("Server: This ticket has been used\n");
            return false;
        }
    }
    spent_m[spent_num++] = h_m_int;
//    printf ("Server::verifying token3\n");
    if (spent_num % 1000 == 0) {
	    printf ("spent_num = %d\n", spent_num);
    }
    return true;
}
