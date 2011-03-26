#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>

typedef uint8_t  byte;

class Client {
public:
    Client();
    ~Client();
    void registration(double revealed_per_interval, int tags_each_reveal, int period_length);
    void reveal(float percentage);
    void payment();
    int cc_bytes; //communication cost in bytes
protected:
    int num_tags;
    byte _i[32]; // unique identifier
    byte ** _m; // array of (H(i,r),H(t,s))
    bool *used; // a tag illustrating weather a token has been used or not

    int ** _t; // array of times

    BIGNUM ** _r; // array of random salt
    BIGNUM ** _s; // array of random salt
    BIGNUM ** _sigma; // array of signatures
    BIO* out;
};

#endif
