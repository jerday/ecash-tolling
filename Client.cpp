#include "Client.hpp"
#include "Server.hpp"

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
	}

	// [TODO]:
	// _i = (some unique identity);

	for(int t = 0; t < num_times; t++) {
		for(int j = 0; j < revealed_per_interval; j++) {
			// For each ticket j*i, the user sets m = (H(i,r),H(t,s)) where r and
			// s are random salts.
			// [TODO]:
			// _m[i*j] = (H(i,r),H(t,s))
		}
	}
}

void Client::reveal() {

}

void Client::payment() {

}
