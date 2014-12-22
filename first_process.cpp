#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <process.h>

#define BUF_SIZE 256 * 1024 * 1024
TCHAR szName[] = TEXT("\\FileMappingObject.dat");
TCHAR szMsg[] = TEXT("2");

typedef  unsigned(__stdcall *START_ADDRESS)(void *);


struct ThreadInfo {
	LPCSTR pBuf;
	HANDLE hFile;
	LONG offset;
	ThreadInfo() {
		pBuf = NULL;
	}
};

LONG ThreadInfiniteFunction(LPVOID lpV){
	ThreadInfo* threadInfo = (ThreadInfo*)lpV;
	LONG offset = threadInfo->offset = 0;
	PVOID mem_offset = (PVOID)threadInfo->pBuf;
	for (long i = 0; i < 1024 * 50000; ++ i){
		offset = strlen((char*)mem_offset);
		//offset = GetFileSize(threadInfo->hFile, NULL);

		if (offset + (_tcslen(szMsg) * sizeof(TCHAR)) >= BUF_SIZE)
			break;
		mem_offset = (TCHAR*)mem_offset + offset;
		threadInfo->offset += offset;
		try{
			CopyMemory(mem_offset, szMsg, (_tcslen(szMsg) * sizeof(TCHAR)));
		}
		catch (...){
			return 1;
		}
	}
	return 0;
}

long fileContentSize(LPCSTR FileMap){
	long result = 0;
	while(FileMap[0]){
		FileMap ++;
		result ++;
	}
	return result;
}

int _tmain()
{
	TCHAR dir[200];
	if(!GetCurrentDirectory(200, dir))
		return 1;
	TCHAR *szFullName = strcat(dir, szName);
	HANDLE hMapFile;
	LPCTSTR pBuf;
	HANDLE hFile = CreateFileA(szFullName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);

	//LONG file_sz = GetFileSize(hFile, NULL);

	hMapFile = CreateFileMapping(
		hFile,    // use paging file
		NULL,                    // default security
		PAGE_READWRITE,          // read/write access
		0,                       // maximum object size (high-order DWORD)
		BUF_SIZE,                // maximum object size (low-order DWORD)
		NULL);                 // name of mapping object

	if (hMapFile == NULL)
	{
		_tprintf(TEXT("Could not create file mapping object (%d).\n"),
			GetLastError());
		return 1;
	}
	pBuf = (LPTSTR)MapViewOfFile(hMapFile,   // handle to map object
		FILE_MAP_ALL_ACCESS, // read/write permission
		0,
		0,
		0);

	if (pBuf == NULL)
	{
		_tprintf(TEXT("Could not map view of file (%d).\n"),
			GetLastError());

		CloseHandle(hMapFile);

		return 1;
	}
	LONG file_sz = fileContentSize(pBuf);
	ThreadInfo threadInfo;
	threadInfo.pBuf = pBuf;
	//threadInfo.offset = file_sz;
	
	pBuf = (TCHAR*)pBuf + file_sz; // Let's declare buffer to the end of file.
	HANDLE* hThreads = new HANDLE[1];
	hThreads[0] = (HANDLE)_beginthreadex(0, 0, (START_ADDRESS)ThreadInfiniteFunction, &threadInfo, 0, 0);
	if (WaitForMultipleObjects(1, hThreads, TRUE, INFINITE) == WAIT_OBJECT_0){

		CloseHandle(hThreads[0]);
		if(!UnmapViewOfFile(pBuf)) printf("Cold not set Unmap File View: %d\n", GetLastError());
		//FlushViewOfFile(pBuf, threadInfo.offset);
		CloseHandle(hMapFile);
		SetFilePointer(hFile, threadInfo.offset, 0, 0);
		//if(!SetFileValidData(hFile, threadInfo.offset)) printf("Cold not set file valid data: %d\n", GetLastError());

		if(!SetEndOfFile(hFile)) printf("Cold not set EOF: %d\n", GetLastError());
		CloseHandle(hFile);
		
	}
	printf("Process is loaded. Press any key to finish.");
	_getch();
	delete[] hThreads;
	return 0;
}