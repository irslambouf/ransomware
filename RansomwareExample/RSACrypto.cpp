#include <iostream>
#include <openssl\bn.h>

#include "RSACrypto.h"

RSACrypto::RSACrypto()
{	
	cb = BN_GENCB_new();

	bn = BN_new();
	if (!BN_set_word(bn, RSA_F4)) {
		std::cout << "Failed to assign the exponent, stopping" << std::endl;
		free_all();
	}

	rsa = RSA_new();
	if (!RSA_generate_key_ex(rsa, bit_size, bn, cb)) {
		std::cout << "Failed to generate key pair, stopping" << std::endl;
		free_all();
	}
}

RSACrypto::~RSACrypto()
{
	free_all();
}

void RSACrypto::free_all() {
	BN_free(bn);
	BN_GENCB_free(cb);
	RSA_free(rsa);
	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
}
