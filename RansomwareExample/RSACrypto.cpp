#include <iostream>
#include <openssl\bn.h>
#include <openssl\rsa.h>

#include "RSACrypto.h"

RSACrypto::RSACrypto()
{	
	bn = BN_new();
	if (!BN_set_word(bn, RSA_F4)) {
		std::cout << "Failed to assign the exponent, stopping" << std::endl;
		free_all();
	}

	rsa = RSA_new();
	if (!RSA_generate_key_ex(rsa, bit_size, bn, NULL)) {
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
	RSA_free(rsa);
}

int RSACrypto::encrypt_key(std::wstring& path, const unsigned char * key) {
	unsigned char * out_buffer = new unsigned char[RSA_size(rsa)];
	int result;

}

int RSACrypto::decrypt_key(std::wstring& path, const unsigned char * key) {

}