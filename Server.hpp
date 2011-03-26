#ifndef SERVER_HPP
#define SERVER_HPP

#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <stdint.h>
#include <iostream>
#include <sqlite3.h>

using namespace std;

typedef uint8_t byte;

class Server {
public:
    static void key_generation();
    static void registration();
    static bool verify_token(byte *h, int *t, BIGNUM * s, BIGNUM * sigma);
    static void payment();
    static BIGNUM * compute_gamma(BIGNUM * c,BN_CTX * bnCtx);
    static BIGNUM * get_n();
    static BIGNUM * get_e();
    static BIGNUM * get_d();
    static int bytes_stored;
    static sqlite3* db;
    static sqlite3* ds_db;

private:
    static RSA * rsa;
    static SHA256_CTX sha256;
    static BIO* out;

    static int * spent_m;
    static int spent_num;
};

#endif
