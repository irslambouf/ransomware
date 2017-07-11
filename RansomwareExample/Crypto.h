#ifndef CRYPTO_H
#define CRYPTO_H

#include <fstream>

class Crypto {
public:
	Crypto();
	Crypto(const Crypto& orig);
	virtual ~Crypto();
	int encrypt(std::ifstream& in, std::ofstream& out, unsigned char* tag);
	int decrypt(std::ifstream& in, std::ofstream& out, unsigned char* tag);
private:
	unsigned char key[32];
	unsigned char iv[16];
};

#endif /* CRYPTO_H */