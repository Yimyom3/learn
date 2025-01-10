#pragma once
#include "pch.h"

DWORD GetPid(WCHAR* szName);
BOOL PrivilegeDebug();
BOOL ChangeFunc(LPVOID funcAddress,UCHAR buf[], SIZE_T size);
VOID ExecShellCode(LPVOID shellCode,SIZE_T size);
DWORDLONG GetPhysicalMemory();
BOOL CheckPrivilege();
BOOL GetSystemProcess(DWORD pid);