#include <iostream>
#include <fstream>
#include <openssl\bn.h>
#include <openssl\rsa.h>

#include <boost\filesystem.hpp>

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

int RSACrypto::encrypt_key(std::wstring& out_path, const unsigned char * from, int length) {
	/* Encrypt AES key and GCM tag with RSA public key */
	unsigned char *buffer = new unsigned char[RSA_size(rsa)];
	int ciphertext_len;
	int size = RSA_size(rsa);
	ciphertext_len = RSA_public_encrypt(length, from, buffer, rsa, RSA_PKCS1_PADDING);
	
	std::ofstream out_file;
	out_file.open(out_path, std::ios::binary | std::ios::out);
	if (!out_file.is_open()) {
		printf("File is NOT open");
	}
	out_file.write((const char *)buffer, RSA_size(rsa));
	out_file.flush();
	out_file.close();

	delete buffer;
	buffer = NULL;

	return ciphertext_len;
}

int RSACrypto::decrypt_key(std::wstring& key_path, unsigned char * to) {
	std::ifstream file(key_path, std::ios::binary);
	unsigned char *enc_buffer = new unsigned char[RSA_size(rsa)];
	file.read((char *)enc_buffer, RSA_size(rsa));	// Read data from file
	file.close();

	boost::filesystem::remove(key_path);	// Delete file
	int plaintext_len;
	plaintext_len = RSA_private_decrypt(RSA_size(rsa), enc_buffer, to, rsa, RSA_PKCS1_PADDING);

	return plaintext_len;
}