#include "Server.hpp"

void Server::key_generation() {
	// Server selects an RSA modulus N = pq and determines e, d such
	// that ed ≡ 1 (mod phi(N)). The public key is (e,N), the private
	// key is (d,p,q).
}
void Server::registration() {

}

void Server::sign() {
	// Compute blinded signature and return it.
}
