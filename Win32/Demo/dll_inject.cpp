#include "dll_inject.h"

VOID WritePath(DWORD pid, WCHAR* szPath, HANDLE* lpProcess, LPVOID* lpRemoteAddress)//���1��Ŀ�����PID  ���2��DLL·�� ����3:Ŀ����̾�� ����4: Զ�̽�����д��dll·���ĵ�ַ
{
    //һ����Ŀ�����������һ���ռ�
    *lpProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!(*lpProcess)) {
        cout << "error1 " << GetLastError() << endl;
        return;
    }

    size_t size = (wcslen(szPath) + 1) * sizeof(WCHAR);
    *lpRemoteAddress = VirtualAllocEx(*lpProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (!(*lpRemoteAddress)) {
        cout << "error2 " << GetLastError() << endl;
        CloseHandle(*lpProcess);
        return;
    }

    //���� ��dll��·��д�뵽Ŀ����̵��ڴ�ռ���

    BOOL bRet = WriteProcessMemory(*lpProcess, *lpRemoteAddress, szPath, size, NULL);
    if (!bRet) {
        cout << "error3 " << GetLastError() << endl;
        VirtualFreeEx(*lpProcess, *lpRemoteAddress, 0, MEM_RELEASE);
        CloseHandle(*lpProcess);
    }
}


FARPROC GetLoadLibraryAddress(HMODULE hModule) {
    FARPROC LLib;
    LLib = GetProcAddress(hModule, "LoadLibraryW");
    CloseHandle(hModule);
    return LLib;
}

FARPROC GetZwCreateThreadExAddress(HMODULE hModule) {
    FARPROC ZCTE;
    ZCTE = GetProcAddress(hModule, "ZwCreateThreadEx");
    CloseHandle(hModule);
    return ZCTE;
}

FARPROC GetCreateUserThreadAddress(HMODULE hModule) {
    FARPROC ZCTE;
    ZCTE = GetProcAddress(hModule, "RtlCreateUserThread");
    CloseHandle(hModule);
    return ZCTE;
}

VOID CreateRemoteThreadInject(DWORD pid, WCHAR* szPath) {
    HMODULE k32Module;
    HANDLE hProcess = NULL;
    LPVOID pRemoteAddress = NULL;
    HANDLE hThread = NULL;

    k32Module = GetModuleHandle(L"kernel32.dll");
    if (k32Module) {
        WritePath(pid, szPath, &hProcess, &pRemoteAddress);
        if (hProcess && pRemoteAddress) {
            hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetLoadLibraryAddress(k32Module), pRemoteAddress, NULL, NULL); //LPTHREAD_START_ROUTINE���ڽ�������ַ��Ϊ�߳̽�Ҫִ�еĺ���������ǿת
            if (hThread) {
                WaitForSingleObject(hThread, INFINITE);
                VirtualFreeEx(hProcess, pRemoteAddress, 0, MEM_RELEASE);
                CloseHandle(hThread);
            }
            CloseHandle(hProcess); 
        }
    }
}

VOID NtCreateThreadExInject(DWORD pid, WCHAR* szPath) {
    HMODULE k32Module;
    HMODULE ntModule;
    DWORD th;
    HANDLE hThreadHandle;
    PfnZwCreateThreadEx ZwCreateThreadEx;
    HANDLE hProcess = NULL;
    LPVOID pRemoteAddress = NULL;

    k32Module = GetModuleHandle(L"kernel32.dll");
    ntModule = GetModuleHandle(L"ntdll.dll");
    if (k32Module && ntModule) {
        ZwCreateThreadEx = (PfnZwCreateThreadEx)GetZwCreateThreadExAddress(ntModule);
        if (ZwCreateThreadEx) {
            WritePath(pid, szPath, &hProcess, &pRemoteAddress);
            if (hProcess && pRemoteAddress) {
                th = ZwCreateThreadEx(&hThreadHandle, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)GetLoadLibraryAddress(k32Module), pRemoteAddress, 0, 0, 0, 0, NULL);
                if (hThreadHandle) {
                    WaitForSingleObject(hProcess, 5000);
                    VirtualFreeEx(hProcess, pRemoteAddress, 0, MEM_RELEASE);
                    CloseHandle(hProcess);
                    CloseHandle(hThreadHandle);
                }
            }
        }
    }
}

VOID RtCreateUserThreadInject(DWORD pid, WCHAR* szPath) {
    HMODULE k32Module;
    HMODULE ntModule;
    BOOL status;
    pRtlCreateUserThread createUserThread;
    HANDLE hThread = NULL;
    HANDLE hProcess = NULL;
    LPVOID pRemoteAddress = NULL;

    k32Module = GetModuleHandle(L"kernel32.dll");
    ntModule = GetModuleHandle(L"ntdll.dll");
    if (k32Module && ntModule) {
        createUserThread = (pRtlCreateUserThread)GetCreateUserThreadAddress(ntModule);
        if (createUserThread) {
            WritePath(pid, szPath, &hProcess, &pRemoteAddress);
            if (hProcess && pRemoteAddress) {
                status = createUserThread(hProcess, NULL, 0, 0, 0, 0, GetLoadLibraryAddress(k32Module), pRemoteAddress, &hThread, NULL);
                if (status >=0 ) {
                    WaitForSingleObject(hThread, INFINITE);
                    VirtualFreeEx(hProcess, pRemoteAddress, 0, MEM_RELEASE);
                    CloseHandle(hProcess);
                }
            }
        }
    }
}