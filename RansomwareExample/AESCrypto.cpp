#include "AESCrypto.h"

#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <iostream>

AESCrypto::AESCrypto() {
	if (!RAND_bytes(aes_key, sizeof(aes_key))) {
		std::cout << "Error generating key bytes" << std::endl;
	}
}

AESCrypto::AESCrypto(const unsigned char * key) {
	memcpy(aes_key, key, sizeof(aes_key));
}

AESCrypto::AESCrypto(const AESCrypto& orig) {
}

AESCrypto::~AESCrypto() {
}

int AESCrypto::encrypt(std::ifstream& in, std::ofstream& out, unsigned char* tag) {
	// Generate IV
	unsigned char aes_iv[AES_BLOCK_SIZE];	// AES_BLOCK_SIZE = 16
	if (!RAND_bytes(aes_iv, sizeof(aes_iv))) {
		std::cout << "Error generating iv bytes" << std::endl;
		return 0;
	}
	
	EVP_CIPHER_CTX *ctx;
	unsigned char in_buffer[AES_BLOCK_SIZE]; // AES_BLOCK_SIZE = 16
	unsigned char out_buffer[AES_BLOCK_SIZE];
	int len, ciphertext_len = 0;

	/* Create and initialize the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		return -1;
	}
	/* Set cipher type and mode */
	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		return -1;
	}
	/* Set IV length to 128 bit */
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(aes_iv), NULL)) {
		return -1;
	}
	/* Initialize key and IV */
	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, aes_iv)) {
		return -1;
	}
	/* Write IV to file */
	out.write((const char *)aes_iv, sizeof(aes_iv));

	while (!in.eof()) {
		in.read((char *)in_buffer, AES_BLOCK_SIZE);
		int read_bytes = in.gcount();

		/* Encrypt plaintext */
		if (!EVP_EncryptUpdate(ctx, out_buffer, &len, in_buffer, read_bytes)) {
			return -1;
		}
		ciphertext_len += len;
		out.write((const char *)out_buffer, len);
	}
	if (!EVP_EncryptFinal_ex(ctx, out_buffer, &len)) {
		return -1;
	}
	ciphertext_len += len;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
		return -1;
	}

	EVP_CIPHER_CTX_free(ctx);
	out.write((char *)out_buffer, len);
	out.flush();
	out.close();
	in.close();

	return ciphertext_len;
}

int AESCrypto::decrypt(std::ifstream& in, std::ofstream& out, unsigned char* tag) {
	EVP_CIPHER_CTX *ctx;
	unsigned char in_buffer[AES_BLOCK_SIZE]; // AES_BLOCK_SIZE = 16
	unsigned char out_buffer[AES_BLOCK_SIZE];
	unsigned char iv_buffer[AES_BLOCK_SIZE];
	int len, ret, plaintext_len = 0;

	/* Create and initialize the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		return -1;
	}
	/* Set cipher type and mode */
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		return -1;
	}

	in.read((char *)iv_buffer, AES_BLOCK_SIZE);

	/* Set IV length to 128 bit */
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AES_BLOCK_SIZE, NULL)) {
		return -1;
	}

	/* Initialize key and IV */
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv_buffer)) {
		return -1;
	}

	while (!in.eof()) {
		in.read((char *)in_buffer, AES_BLOCK_SIZE);
		int read_bytes = in.gcount();

		/* Decrypt plaintext */
		if (!EVP_DecryptUpdate(ctx, out_buffer, &len, in_buffer, read_bytes)) {
			return -1;
		}
		plaintext_len += len;
		out.write((const char *)out_buffer, len);
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
		return -1;
	}

	/* Finalize the decryption. A positive return value indicates success,
	* anything else is a failure - the plaintext is not trustworthy.
	*/
	ret = EVP_DecryptFinal_ex(ctx, out_buffer, &len);
	/* Clean up regardless of success */
	EVP_CIPHER_CTX_free(ctx);

	out.write((char *)out_buffer, len);
	plaintext_len += len;

	out.flush();
	out.close();
	in.close();

	if (ret) {
		return plaintext_len;
	}
	else {
		return -1;
	}
}

void AESCrypto::get_aes_key(unsigned char * dest) {
	memcpy(dest, aes_key, sizeof(aes_key));
}