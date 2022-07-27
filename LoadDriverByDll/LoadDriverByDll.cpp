// LoadDriverByDll.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include "string.h"



extern "C" typedef BOOL (__cdecl * LoadDriver)(char* lpszDriverName, char* lpszDriverPath);
extern "C" typedef BOOL (__cdecl * UnloadDriver)(char* szSvrName);
extern "C" typedef BOOL (__cdecl * DeviceControl)(_In_ char* lpszDriverName, _In_ LPWSTR ProtectProcessName, _In_ ULONG_PTR ProtectProcessPid);
int main()
{

	

	HMODULE _hDllInst = LoadLibraryW(L"LoadDriverByPs.dll");
	
	
	LoadDriver LoadDriverFunction = (LoadDriver)GetProcAddress(_hDllInst,"LoadDriver");
	UnloadDriver UnloadDriverFunction = (UnloadDriver)GetProcAddress(_hDllInst, "UnloadDriver");
	DeviceControl DeviceControlFunction = (DeviceControl)GetProcAddress(_hDllInst, "DeviceControl");


	LoadDriverFunction((char*)"ProcessProtect",(char*)"ProcessProtect.sys");
	

	DeviceControlFunction((char*)"ProcessProtect", (LPWSTR)L"LoadDriverByDll.exe", GetCurrentProcessId());


	//UnloadDriverFunction((char*)"ProcessProtect");
	
	
	FreeLibrary(_hDllInst);
	
	Sleep(30000);

	
	
}


