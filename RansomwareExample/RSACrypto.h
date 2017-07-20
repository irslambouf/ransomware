#pragma once

#include <openssl\rsa.h>
#include <string>

class RSACrypto
{
public:
	RSACrypto();
	~RSACrypto();
	int save_keys(std::wstring path);
	int save_keys(std::wstring in_path, std::wstring out_path);
	int save_pub_key(std::wstring path);
	int save_priv_key(std::wstring path);
private:
	const int bit_size = 4096;
	RSA* rsa = NULL;
	BN_GENCB* cb = NULL;
	BIGNUM* bn = NULL;
	BIO* bp_public = NULL;
	BIO* bp_private = NULL;
	void free_all();
};

