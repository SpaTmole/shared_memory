#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <process.h>
#include <string>
#include <cmath>

#define LODWORD(_qw)    ((DWORD)(_qw))
#define HIDWORD(_qw)    ((DWORD)(((_qw) >> 32) & 0xffffffff))

#define BUF_SIZE 256 * 1024 * 1024
TCHAR szName[] = TEXT("\\FileMappingObject.dat");
//TCHAR szMsg[] = TEXT("1");

typedef  unsigned(__stdcall *START_ADDRESS)(void *);

HANDLE ghMutex;  // Global Mutex for restricted access from several processes.

LONG fileContentSize(LPCSTR FileMap){
	LONG result = 0;
	while(FileMap[0]){
		FileMap ++;
		result ++;
	}
	return result;
}

struct MappedFileStats {
	LONG fileSize;
};


LONG requestFileSize(HANDLE& hOriginFile, HANDLE& hMapStatFile, DWORD newSize){
	/*
	Function requests from additional shared file position of main file. 
	If param DWORD newSize is not NULL, then function will setup new file size to additional mapped file.
	Always returns size of main file.

	CAUTION: use within mutex to provide one-time access for each process.
	*/
	DWORD* pBuf =  (DWORD*)MapViewOfFile(hMapStatFile,   // handle to map object
		FILE_MAP_ALL_ACCESS, // read/write permission
		0,
		0,
		NULL);
	if (newSize) {
		pBuf[0] = newSize;
		if (!FlushViewOfFile(pBuf, sizeof(newSize))) printf("Could not flushed File View: %d\n", GetLastError());
	} else {
		newSize = pBuf[0];
		if (!newSize) {
			GetFileSize(hOriginFile, &newSize);
		}
	}
	if (!UnmapViewOfFile(pBuf)) printf("Could not Unmap Stat File View: %d\n", GetLastError());
	return newSize;
}


BOOL protectedWriting (HANDLE& hFile, HANDLE& hMapFile, HANDLE& hMapStatFile, TCHAR* msg) {
	LPVOID pBuf;
	LONG file_sz;
	LONG szMsg = 0;
	LONG alloc = 0;
	switch (WaitForSingleObject(ghMutex, // handle to mutex
		                        INFINITE))
	{
		// The thread got ownership of the mutex
		case WAIT_OBJECT_0:
			__try {
				szMsg = _tcslen(msg) * sizeof(TCHAR);
				file_sz = requestFileSize(hFile, hMapStatFile, NULL);
				alloc = (1 << 16) * (( file_sz / 4096 ) + 1);
				
				pBuf = MapViewOfFile(hMapFile,   // handle to map object
					FILE_MAP_ALL_ACCESS, // read/write permission
					0,
					0,
					alloc);  // TODO: Doesn't properly work if change to granullary size.
				if (pBuf == NULL) {
					_tprintf(TEXT("Could not map view of file (%d).\n"),
					GetLastError());
					return FALSE;
				}
				if (file_sz + szMsg < BUF_SIZE) {
					//CopyMemory((LPVOID)((TCHAR*)pBuf + file_sz), msg, szMsg);
					strcpy((LPTSTR)pBuf + (DWORD)std::ceil((FLOAT)file_sz / sizeof(TCHAR)), msg);
				}
				
				//if (!FlushViewOfFile(pBuf, 0)) printf("Could not flushed File View: %d\n", GetLastError());
				if (!UnmapViewOfFile(pBuf)) printf("Could not set Unmap File View: %d\n", GetLastError());
				requestFileSize(hFile, hMapStatFile, file_sz + szMsg);
				SetFilePointer(hFile, file_sz + szMsg, 0, 0);
				
				
			}
			__finally {
				if (!ReleaseMutex(ghMutex)) {
					return FALSE;
				}
			}
		break;
		case WAIT_ABANDONED:
			return FALSE;
	}
	return TRUE; 
}

int _tmain(DWORD argc, TCHAR *argv[])
{
	HANDLE hFile, hMapFile, hStatFile, hMapStatFile;
	
	if (argc < 2)
		return 2;
	TCHAR dir[200];
	if(!GetCurrentDirectory(200, dir))
		return 1;
	std::string lpszFileName = std::string(dir) + std::string(szName);
	std::string lpszStatFileName = std::string(dir) + std::string("\\stat.dat");
	
	TCHAR* szMsg = argv[1];

	ghMutex = CreateMutex( 
        NULL,              // default security attributes
        FALSE,             // initially not owned
        "CommonMutex"
	);             
	hFile = CreateFileA(lpszFileName.c_str(), GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);

	hMapFile = CreateFileMapping(
		hFile,    // use paging file
		NULL,                    // default security
		PAGE_READWRITE,          // read/write access
		0,                       // maximum object size (high-order DWORD)
		BUF_SIZE,                // maximum object size (low-order DWORD)
		"TestMapping");                 // name of mapping object

	hStatFile = CreateFileA(lpszStatFileName.c_str(), GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);

	hMapStatFile = CreateFileMapping(
		hStatFile,    // use paging file
		NULL,                    // default security
		PAGE_READWRITE,          // read/write access
		0,                       // maximum object size (high-order DWORD)
		8,                // maximum object size (low-order DWORD)
		"TestStatMapping");                 // name of mapping object
	if (hMapStatFile == NULL) {
		_tprintf(TEXT("Could not create file mapping object (%d).\n"),
			GetLastError());
		return 1;
	}
	for(LONG i = 0; i < 1024 * 50; ++ i) {
		if (!protectedWriting(hFile, hMapFile, hMapStatFile, szMsg)) {
			CloseHandle(hMapStatFile);
			CloseHandle(hStatFile);
			CloseHandle(hMapFile);
			if (!SetEndOfFile(hFile)) printf("Cold not set EOF: %d\n", GetLastError());
			CloseHandle(hFile);
			return 1;
		}
	}
	CloseHandle(hMapStatFile);
	CloseHandle(hStatFile);
	CloseHandle(hMapFile);
	if (!SetEndOfFile(hFile)) printf("Cold not set EOF: %d\n", GetLastError());
	CloseHandle(hFile);
	return 0;
}