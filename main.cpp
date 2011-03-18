#include "Client.hpp"
#include "Server.hpp"
#include <iostream>

int main(int argc, char** argv)
{
	Server::key_generation();
	Client c = Client();
	c.registration(1,1,30);
	return 0;
}

