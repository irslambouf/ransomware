#pragma once

#include <openssl\rsa.h>
#include <string>

class RSACrypto
{
public:
	RSACrypto();
	RSACrypto(RSA* rsa);
	~RSACrypto();
	int encrypt_key(std::wstring& path, const unsigned char * key_and_tag, int length);
	int decrypt_key(std::wstring& path, unsigned char * key_and_tag);
	RSA* get_rsa();
	void free_all();
private:
	const int bit_size = 4096;
	RSA* rsa = NULL;
	BIGNUM* bn = NULL;
};

