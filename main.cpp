#include "Client.hpp"
#include "Server.hpp"
#include <iostream>

int main(int argc, char** argv)
{
    Server::key_generation();
    Server::registration();
    Client c = Client();
    c.registration(0.2,1,30);
    c.reveal(0.5);
    printf ("Total communication cost = %d bytes\n", c.cc_bytes);
    //}
    return 0;
}

