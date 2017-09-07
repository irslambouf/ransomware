## Prerequisits

- OpenSSL 1.1.0+
- Boost 1.64+
- Perl 5.24.1+

## Build system
- Windows 10 x64, version 1703, Build 15063.483
- i7-6700

Build OpenSSL static linked libs
- 
1. Get openSSL source
```
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout --track origin/OpenSSL_1_1_0-stable
```
2. Build OpenSSL

- open `visual studio 2017 command line x64 build tool`
- go to `openssl` folder
```
perl Configure no-asm no-shared VC-WIN64A
nmake
nmake test
nmake install
```
Configure VS2017 for OpenSSL
-
1. In Solution Explorer (top-right)
2. right click project > Properties
3. C/C++ > General
4. Add openssl include dir under Additional Include Directories
    ex: C:\Program Files\OpenSSL\include;%(AdditionalIncludeDirectories)
5. Linker -> General
6. Add openssl lib dir under Additional Library Directories
> ex: C:\Program Files\OpenSSL\lib
7. Linker -> Input
8. Add openssl and windows libs under Additional Dependencies
- Crypt32.lib ( Windows lib ) needed by libcrypto static linking
- WS2_32.lib ( Windows lib ) needed by libcrypto static linking
- libcrypto.lib ( OpenSSL lib )
> ex: Crypt32.lib;WS2_32.lib;libcrypto.lib;kernel32.lib;user32.lib;gdi32.lib;winspool.lib;comdlg32.lib;advapi32.lib;shell32.lib;ole32.lib;oleaut32.lib;uuid.lib;odbc32.lib;odbccp32.lib;%(AdditionalDependencies)


Build Boost static linked lib 
-
1. Download from http://www.boost.org/users/download/        (Im using 1.64)
2. extract folder
3. open `visual studio 2017 command line x64 build tool`
4. navigate to `(Boost folder)\tools\build\` folder
5. Run `bootstrap.bat`
6. Run the b2 command below
```
.\b2 -q -with-filesystem -j4 toolset=msvc-14.1 address-model=64 architecture=x86 link=static runtime-link=static
```
> -q Stop when at first error

> -with-filesystem will only build the filesystem library

> -j4 Use 4 cores to build

> toolset=msvc-14.1 is used to tell b2 that it should use the VS2017 toolset

> address-model=64 is for x64 OS (windows 10)

> link=static to build static library

> runtime-link=static to build static library that will not require dynamic library to be installed 

Configure VS2017 for Boost
-
At the end of building boost the command line toold should say something like:
```
The Boost C++ Libraries were successfully built!

The following directory should be added to compiler include paths:

    C:\boost_1_64_0

The following directory should be added to linker library paths:

    C:\boost_1_64_0\stage\lib
```

1. In Solution Explorer (top-right)
2. right click project > Properties
3. C/C++ > General
4. Add the boost include dir as mentioned above under Additional Include Directories
> ex: C:\boost_1_64_0;C:\Program Files\OpenSSL\include;%(AdditionalIncludeDirectories)
5. C/C++ > Code Generation
6. Runtime Library set to Multi-threaded Debug (/MTd)
7. Linker > General
8. Add the boost lib dir as mentioned above under Additional Library Directories
> ex: C:\Program Files\OpenSSL\lib;C:\boost_1_64_0\stage\lib

Configure VS2017 for admin rights
1. In Solution Explorer (top-right)
2. right click project > Properties
3. Linker > Manifest File
4. set: UAC Execution Level to: requireAdministrator (/level='requireAdministrator')
5. set: UAC bypass UI protection to : No (/uiAccess='false')

