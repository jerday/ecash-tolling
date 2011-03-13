#include "Client.hpp"
#include "Server.hpp"

Client::Client() {
	_m = std::vector<char[32]>();
	_r = std::vector<char[32]>();
	_sigma = std::vector<char[32]>();
	_t = std::vector<char[32]>();
}

Client::~Client() {

}

void Client::registration() {
	// 1. Client selects random m1,...,mk corresponding to
	// time intervals t1,...,tk.


}

void Client::reveal() {

}

void Client::payment() {

}
