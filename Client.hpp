#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <vector>

class Client {
public:
	Client();
	~Client();
	void registration();
	void reveal();
	void payment();
protected:
	std::vector<char[32]> _m;
	std::vector<char[32]> _t;
	std::vector<char[32]> _r;
	std::vector<char[32]> _sigma;

};

#endif
