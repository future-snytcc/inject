#include <stdio.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>

using namespace std;

DWORD tarPID = 0;
const TCHAR *tarProName = L"PlantsVsZombies.exe";		//目标进程
const TCHAR* injectDLLName = L"libcef.dll";				//这个DLL要么用绝对路径，要么放在目标进程的根目录下

/// <summary>
/// 创建进程快照获取目标进程PID
/// </summary>
/// <param name="name"></param>
/// <returns></returns>
BOOL getTargetProcessPID(const TCHAR *name)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	BOOL flag = Process32First(hSnapshot,&pe32);
	while (flag) {
#ifdef _DEBUG
		wcout << pe32.szExeFile << endl;
#endif
		if (!wcscmp(pe32.szExeFile, name)) {
			tarPID = pe32.th32ProcessID;
			CloseHandle(hSnapshot);
			return true;
		}
		flag = Process32Next(hSnapshot, &pe32);
	}
	CloseHandle(hSnapshot);
	return false;
}


/// <summary>
/// 注入dll
/// </summary>
/// <returns></returns>
BOOL injectDLL()
{
	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
	if (!hKernel32) {
		cout << "获取kernel32.dll模块失败!" << endl;
		return false;
	}
	//打开目标进程
	HANDLE hPro = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tarPID);
	if (NULL == hPro) {
		cout << "进程打开失败!" << endl;
		return false;
	}

	//向目标进程申请内存空间
	LPVOID DLLAddr = VirtualAllocEx(hPro,NULL,wcslen(injectDLLName) * 2 + 2, MEM_COMMIT, PAGE_READWRITE);
	if (!DLLAddr) {
		cout << "进程内申请内存失败!" << endl;
		return false;
	}

	//向申请的空间写入数据
	SIZE_T writeSize = 0;
	if (!WriteProcessMemory(hPro, DLLAddr, injectDLLName, wcslen(injectDLLName) * 2 + 2, &writeSize)) {
		cout << "写进程内存失败!" << endl;
		return false;
	}

	//获取LoadLibraryW函数地址
	typedef HMODULE (*pLoadLibrary) (_In_ LPCWSTR lpLibFileName);
	pLoadLibrary mLoadLibrary = NULL;
	mLoadLibrary = (pLoadLibrary)GetProcAddress(hKernel32,"LoadLibraryW");

	//创建远程线程，mLoadLibrary指向在远程线程中执行的函数地址
	HANDLE hRemoteThread = CreateRemoteThread(hPro,NULL,0, (LPTHREAD_START_ROUTINE)mLoadLibrary, DLLAddr,0,NULL);
	if (!hRemoteThread) {
		cout << "创建远程线程失败!" << endl;
		return false;
	}
	CloseHandle(hPro);
	return true;
}

int main()
{
	if (!getTargetProcessPID(tarProName)) {
		cout << "目标进程未找到!" << endl;
		return 0;
	}
	cout << "找到目标进程!" << endl;
	if (!injectDLL()) {
		return 0;
	}
	cout << "注入成功!" << endl;

	return 1;
}


