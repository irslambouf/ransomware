
#include <cstdlib>
#include <iostream>
#include <boost\filesystem.hpp>

using namespace std;
using namespace boost::filesystem;

int main(int argc, char* argv[]) {
	path root("C:\\");
	try
	{
		recursive_directory_iterator dir(root);
		for (path p : dir) {
			cout << p << endl;
		}
	}

	catch (const filesystem_error& ex)
	{
		cout << ex.what() << '\n';
	}
	
	system("pause");
	return 0;
}