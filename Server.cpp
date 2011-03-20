#include "Server.hpp"
#include <iostream>

RSA * Server::rsa = NULL;

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
	return(-1);
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
//	BN_mod_exp(gamma,c,rsa->d,rsa->n,bnCtx);
	RSA_eay_mod_exp(gamma, c, rsa, bnCtx);

	return gamma;
}

void Server::registration() {
	spent_m = new byte*[24 * 60];
	for (int i = 0; i < 24 * 60; ++i) {
		spent_m[i] = new byte [64];
	}
	SHA256_Init(&sha256);
}

BIGNUM * Server::get_n() {
	return rsa->n;
}

BIGNUM * Server::get_e() {
	return rsa->e;
}

bool Server::verify_token (byte * h, int t, BIGNUM * s, BIGNUM * sigma) {
	//compute m = (H(i,r),h)
	//now it is a naive solution, we simply use an array
	byte* _m = new byte [64];
	_m 

	//verifies that t is correct
	//verifies that m has not been used
	//check signature: H(m) = sigma^e
}
