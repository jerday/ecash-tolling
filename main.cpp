#include "Client.hpp"
#include "Server.hpp"
#include <iostream>

int main(int argc, char** argv)
{

	// Clear the database from last run
	system ("rm double_spending.db");
	system ("rm ecash-tolling.db");

	// Generative server key pair
	Server::key_generation();

	// Set up the server databases
	Server::registration();

	for(int i = 0; i < 10; i++) {
		Client c = Client();
		c.registration(1,1,30/*30*/);
		c.reveal(0.5);
		c.payment();
		printf ("Total communication cost = %d bytes\n", c.cc_bytes);
		printf ("Stored Bytes = %d\n", Server::bytes_stored);
	}

	// Close databases
	sqlite3_close(Server::db);
	sqlite3_close(Server::ds_db);

    return 0;

}

