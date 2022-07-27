#pragma once
#include <windows.h>
extern "C" __declspec(dllexport) BOOL __cdecl LoadDriver(char* lpszDriverName, char* lpszDriverPath);
extern "C" __declspec(dllexport) BOOL __cdecl UnloadDriver(char* szSvrName);
extern "C" __declspec(dllexport) BOOL __cdecl DeviceControl(_In_ char* lpszDriverName, _In_ LPWSTR ProtectProcessName, _In_ ULONG_PTR ProtectProcessPid);