#include "Client.hpp"
#include "Server.hpp"
#include <iostream>

int main(int argc, char** argv)
{
	Server::key_generation();
	Server::registration();
	Client c = Client();
	c.registration(1,1,1);
	c.reveal(1.0);
	return 0;
}

