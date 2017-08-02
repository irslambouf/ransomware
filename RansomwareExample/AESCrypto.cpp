#include "AESCrypto.h"

#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#include <boost\filesystem.hpp>

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
		return -1;
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

	bool flag = true;
	while (!in.eof()) {
		in.read((char *)in_buffer, AES_BLOCK_SIZE);
		int read_bytes = in.gcount();
		if (flag) {
			/* Encrypt plaintext */
			if (!EVP_EncryptUpdate(ctx, out_buffer, &len, in_buffer, read_bytes)) {
				return -1;
			}
			ciphertext_len += len;
			flag = false;
		}
		else {
			memcpy(out_buffer, in_buffer, read_bytes);
			len = read_bytes;
			flag = true;
		}

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
	out.write((const char *)out_buffer, len);
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
	bool flag = true;
	while (!in.eof()) {
		in.read((char *)in_buffer, AES_BLOCK_SIZE);
		int read_bytes = in.gcount();
		if (flag) {
			/* Decrypt plaintext */
			if (!EVP_DecryptUpdate(ctx, out_buffer, &len, in_buffer, read_bytes)) {
				return -1;
			}
			plaintext_len += len;
			flag = false;
		}
		else {
			memcpy(out_buffer, in_buffer, read_bytes);
			len = read_bytes;
			flag = true;
		}

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

int AESCrypto::in_place_encrypt(std::wstring& path, unsigned char * tag) {
	std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);

	if (!file.is_open()) {
		printf("Can't open file, returning");
		return -1;
	}

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
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		return -1;
	}
	/* Set IV length to 128 bit */
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(aes_iv), NULL)) {
		return -1;
	}
	/* Initialize key and IV */
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, aes_iv)) {
		return -1;
	}
		
	bool flag = true;
	while (!file.eof()) {
		file.read((char *)in_buffer, AES_BLOCK_SIZE);
		if (flag) {
			int read_bytes = file.gcount();

			/* Encrypt plaintext */
			if (1 != EVP_EncryptUpdate(ctx, out_buffer, &len, in_buffer, read_bytes)) {
				return -1;
			}
			ciphertext_len += len;
			flag = false;

			/* Move write pointer back so we can override */
			if (len < AES_BLOCK_SIZE) {	//	Last block
				file.clear();
				file.seekp(file.gcount() * -1, std::ios::end);	// Override only partial block
				file.write((const char *)out_buffer, len);
				file.flush();
				break;	// We are done encrypting - stop looping
			} else {
				file.seekp(file.gcount() * -1, std::ios::cur);
				file.write((const char *)out_buffer, len);
				file.flush();
			}
			
		}
		else {
			// Skip data encryption
			flag = true;
		}
	}

	if (1 != EVP_EncryptFinal_ex(ctx, out_buffer, &len)) {
		return -1;
	}
	ciphertext_len += len;

	/* Get tag value */
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
		return -1;
	}

	file.write((const char *)out_buffer, len);
	EVP_CIPHER_CTX_free(ctx);

	/* Write IV to file, extending file size by 16 bytes */
	file.clear();
	file.seekp(0, std::ios::end);
	file.write((const char *)aes_iv, sizeof(aes_iv));
	file.flush();
	file.close();

	return ciphertext_len;
}

int AESCrypto::in_place_decrypt(std::wstring& path, unsigned char* tag) {
	std::fstream file(path, std::ios::binary | std::ios::in);

	if (!file.is_open()) {
		printf("Can't open file, returning");
		return -1;
	}

	EVP_CIPHER_CTX *ctx;
	unsigned char in_buffer[AES_BLOCK_SIZE]; // AES_BLOCK_SIZE = 16
	unsigned char out_buffer[AES_BLOCK_SIZE];
	unsigned char iv_buffer[AES_BLOCK_SIZE];
	int len, ret, plaintext_len = 0;

	/* Grab IV at end of file */
	file.seekg(AES_BLOCK_SIZE * -1, std::ios::end);
	file.read((char *)iv_buffer, AES_BLOCK_SIZE);
	file.flush();

	/* Get file size */
	file.seekg(0, std::ios::end);
	long file_size = file.tellg();

	/* resize file, discarding IV bytes */
	file.close();
	file.clear();
	try {
		boost::filesystem::resize_file(path, file_size - AES_BLOCK_SIZE);
	}
	catch (const boost::filesystem::filesystem_error& e) {
		std::cout << e.what() << std::endl;
		std::cout << "Failed decryption, exiting..." << std::endl;
		return -1;
	}
	file.open(path, std::ios::binary | std::ios::in | std::ios::out);

	/* Create and initialize the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		return -1;
	}
	/* Set cipher type and mode */
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		return -1;
	}

	/* Set IV length to 128 bit */
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AES_BLOCK_SIZE, NULL)) {
		return -1;
	}

	/* Initialize key and IV */
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv_buffer)) {
		return -1;
	}

	/* Do actual decryption of ciphertext */
	bool flag = true;
	while (!file.eof()) {
		file.read((char *)in_buffer, AES_BLOCK_SIZE);
		if (flag) {
			int read_bytes = file.gcount();

			/* Decrypt ciphertext */
			if (!EVP_DecryptUpdate(ctx, out_buffer, &len, in_buffer, read_bytes)) {
				return -1;
			}
			plaintext_len += len;
			flag = false;

			// Move write pointer back so we can override
			if (len < AES_BLOCK_SIZE) {	// Last block
				file.clear();
				file.seekp(file.gcount() * -1, std::ios::end);
				file.write((const char *)out_buffer, len);
				file.flush();
				break;
			}
			else {
				file.seekp(file.gcount() * -1, std::ios::cur);
				file.write((const char *)out_buffer, len);
				file.flush();
			}
			
		}
		else {
			// Skip data decryption
			flag = true;
		}
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
		return -1;
	}

	/* Finalize the decryption. A positive return value indicates success,
	* anything else is a failure - the plaintext is not trustworthy.
	*/
	ret = EVP_DecryptFinal_ex(ctx, out_buffer, &len);
	
	file.write((char *)out_buffer, len);
	plaintext_len += len;

	/* Clean up regardless of success */
	EVP_CIPHER_CTX_free(ctx);
	file.flush();
	file.close();

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