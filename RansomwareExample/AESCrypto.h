#ifndef AESCRYPTO_H
#define AESCRYPTO_H

#include <fstream>

class AESCrypto {
public:
	AESCrypto();
	AESCrypto(const unsigned char* key);
	AESCrypto(const AESCrypto& orig);
	virtual ~AESCrypto();
	int encrypt(std::ifstream& in, std::ofstream& out, unsigned char* tag);
	int decrypt(std::ifstream& in, std::ofstream& out, unsigned char* tag);
	int in_place_encrypt(std::wstring& path, unsigned char* tag);
	int in_place_decrypt(std::wstring& path, unsigned char* tag);
	void get_aes_key(unsigned char * dest);
private:
	unsigned char aes_key[32];
};

#endif /* CRYPTO_H */