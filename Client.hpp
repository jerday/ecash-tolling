#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <stdint.h>

typedef uint8_t  byte;

class Client {
public:
	Client();
	~Client();
	void registration(double revealed_per_interval, int tags_each_reveal, int period_length);
	void reveal();
	void payment();
protected:
	byte _i[32]; // unique identifier
	byte ** _m; // array of (H(i,r),H(t,s))
	byte ** _t; // array of times
	byte ** _r; // array of random salt
	byte ** _s; // array of random salt
	byte ** _sigma; // array of signatures
};

#endif
