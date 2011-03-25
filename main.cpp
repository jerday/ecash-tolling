#include "Client.hpp"
#include "Server.hpp"
#include <iostream>

int main(int argc, char** argv)
{
    Server::key_generation();
    Server::registration();
    Client c = Client();
    for (int i = 64; i < 256; i *= 2)
    {
    	c.registration(1,1,i);
    	c.reveal(0.5);
    }
    return 0;
}

