#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <process.h>

#define BUF_SIZE 256
TCHAR szName[]=TEXT("FileMappingObject.dat");
TCHAR szMsg[]=TEXT("Message from first process");

typedef  unsigned(__stdcall *START_ADDRESS)(void *);


struct ThreadInfo {
	LPCSTR pBuf;
	ThreadInfo() {
		pBuf = NULL;
	}
};

void ThreadInfiniteFunction(LPVOID lpV){
	ThreadInfo* threadInfo = (ThreadInfo*)lpV;
	while(TRUE)
		CopyMemory((PVOID)threadInfo -> pBuf, szMsg, (_tcslen(szMsg) * sizeof(TCHAR)));
}

int _tmain()
{
	HANDLE hMapFile;
	LPCTSTR pBuf;

	hMapFile = CreateFileMapping(
					INVALID_HANDLE_VALUE,    // use paging file
					NULL,                    // default security
					PAGE_READWRITE,          // read/write access
					0,                       // maximum object size (high-order DWORD)
					BUF_SIZE,                // maximum object size (low-order DWORD)
					szName);                 // name of mapping object

	if (hMapFile == NULL)
	{
		_tprintf(TEXT("Could not create file mapping object (%d).\n"),
				GetLastError());
		return 1;
	}
	pBuf = (LPTSTR) MapViewOfFile(hMapFile,   // handle to map object
						FILE_MAP_ALL_ACCESS, // read/write permission
						0,
						0,
						BUF_SIZE);

	if (pBuf == NULL)
	{
		_tprintf(TEXT("Could not map view of file (%d).\n"),
				GetLastError());

		CloseHandle(hMapFile);

		return 1;
	}
	ThreadInfo threadInfo;
	threadInfo.pBuf = pBuf;
	HANDLE hThread = (HANDLE)_beginthreadex(0, 0, (START_ADDRESS)ThreadInfiniteFunction, &threadInfo, 0, 0);
	printf("Process is loaded. Press any key to finish.");
	_getch();
	CloseHandle(hThread);
	UnmapViewOfFile(pBuf);
	CloseHandle(hMapFile);

	return 0;
}
