#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
using namespace std;

DWORD GetPid(WCHAR* szName);
BOOL PrivilegeDebug();
BOOL ChangeFunc(LPVOID funcAddress,UCHAR buf[], SIZE_T size);
VOID ExecShellCode(LPVOID shellCode,SIZE_T size);