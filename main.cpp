#include "Client.hpp"
#include "Server.hpp"
#include <iostream>

int main(int argc, char** argv)
{
	system ("rm double_spending.db");
	 system ("rm ecash-tolling.db");
		Server::key_generation();
  		  Server::registration();
  		  Client c = Client();
  		  c.registration(1,1,30 * 10/*30*/);
		    c.reveal(0.5);
 		   c.payment();
		    printf ("Total communication cost = %d bytes\n", c.cc_bytes);
		    printf ("Stored Bytes = %d\n", Server::bytes_stored);
		    sqlite3_close(Server::db);
  		  sqlite3_close(Server::ds_db);
    
    return 0;

}

