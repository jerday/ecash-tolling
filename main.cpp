#include "Client.hpp"
#include "Server.hpp"
#include <iostream>

int main(int argc, char** argv)
{
//	for (int i = 1024; i < 2048 * 2; i *= 2) {
		  system ("rm double_spending.db");
		  system ("rm ecash-tolling.db");
		Server::key_generation();
  		  Server::registration();
  		  Client c = Client();
    //for (int i = 1; i < 32; i *= 2)
   // {
    //	c.registration(1,1,128);
    //	c.reveal(0.5);
//	printf ("Total communication cost = %d bytes\n", c.cc_bytes);
    //}
    //c.registration(0.2,1,30/*30*/);
  		  //c.registration(0.2,1,i/*30*/);
  		  c.registration(1,1,10/*30*/);
		    c.reveal(0.5);
 		   c.payment();
		    printf ("Total communication cost = %d bytes\n", c.cc_bytes);
		    printf ("Stored Bytes = %d\n", Server::bytes_stored);
		    sqlite3_close(Server::db);
  		  sqlite3_close(Server::ds_db);
//	}
    
    return 0;

}

