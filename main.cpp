#include "Client.hpp"
#include "Server.hpp"
#include <iostream>

int main(int argc, char** argv)
{
	Server::key_generation();
    Server::registration();
    Client c = Client();
    //for (int i = 1; i < 32; i *= 2)
   // {
    //	c.registration(1,1,128);
    //	c.reveal(0.5);
//	printf ("Total communication cost = %d bytes\n", c.cc_bytes);
    //}
    c.registration(0.2,1,1/*30*/);
    c.reveal(0.5);
    printf ("Total communication cost = %d bytes\n", c.cc_bytes);
    return 0;

}

