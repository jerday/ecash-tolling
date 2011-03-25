#include "Client.hpp"
#include "Server.hpp"
#include <iostream>

int main(int argc, char** argv)
{
    Server::key_generation();
    Server::registration();
    Client c = Client();
    c.registration(1,1,4);
    c.reveal(0.5);
    return 0;
}

