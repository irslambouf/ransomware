#pragma once

#include <openssl\rsa.h>
#include <string>

class RSACrypto
{
public:
	RSACrypto();
	~RSACrypto();
	int encrypt_key(std::wstring& path, const unsigned char * key_and_tag, int length);
	int decrypt_key(std::wstring& path, unsigned char * key_and_tag);
private:
	const int bit_size = 4096;
	RSA* rsa = NULL;
	BIGNUM* bn = NULL;
	void free_all();
};

