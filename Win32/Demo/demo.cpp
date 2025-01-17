#include "util.h"

BOOL ParentProcessVerify(PWCHAR szName) {
    BOOL state = FALSE;
	DWORD currentPID = GetCurrentProcessId();
    DWORD parentPID = 0;
    HANDLE hprocessSnap;
    PROCESSENTRY32  pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    hprocessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hprocessSnap == INVALID_HANDLE_VALUE) {
        return state;
    }
    if (Process32First(hprocessSnap, &pe32))
    {
        do {
            if (pe32.th32ProcessID == currentPID) {
                parentPID = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hprocessSnap, &pe32));
    }
    if (Process32First(hprocessSnap, &pe32))
    {
        do {
            if (pe32.th32ProcessID == parentPID) {
                state = !_wcsicmp(szName, pe32.szExeFile);
                break;
            }
        } while (Process32Next(hprocessSnap, &pe32));
    }
    CloseHandle(hprocessSnap);
    return state;
}

BOOL GetProcessImageName(PWCHAR processName, PWCHAR exeName, PDWORD dwsize) {
    BOOL state = FALSE;
    DWORD pid = GetPid(processName);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess) {
        state = QueryFullProcessImageNameW(hProcess, 0, exeName, dwsize);
        CloseHandle(hProcess);
        return state;
    }
    return state;
}

BOOL CreatProcessByParent(PWCHAR parentName, PWCHAR filePath) {
    WCHAR parentFilePath[MAX_PATH];
    DWORD size = MAX_PATH;
    DWORD parentPid = GetPid(parentName);
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    PROCESS_INFORMATION newProcess = { 0 };
    STARTUPINFOEXW startInfo = { 0 };
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
                        GetProcessImageName(parentName,parentFilePath,&size);
                        PathRemoveFileSpecW(parentFilePath);
                        state = CreateProcess(NULL, filePath, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, parentFilePath, &startInfo.StartupInfo, &newProcess);
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
            return state;
        }
        return state;
    }
    return state;
}


BOOL ChangeProcessInformation(PWCHAR parentName) {
    WCHAR filePath[33];
    DWORD Length = MAX_PATH;
    BOOL state = FALSE;
    state = GetProcessImageName(parentName, filePath, &Length);
    if (state) {
        USHORT MaximumLength = (Length + 1) * 2;
        LPVOID TEB = NtCurrentTeb();
        LPVOID PEB = (LPVOID) * (PDWORD64)((BYTE*)TEB + 0x60);
        LPVOID ProcessParameters = (LPVOID) * (PDWORD64)((BYTE*)PEB + 0x20);
        LPVOID PImagePathName = (LPVOID)((BYTE*)ProcessParameters + 0x60);
        *(PUSHORT)((BYTE*)PImagePathName) = (USHORT)(Length * 2);
        *(PUSHORT)((BYTE*)PImagePathName + 2) = MaximumLength;
        *(PWSTR*)((BYTE*)PImagePathName + 8) = filePath;
        LPVOID PCommandLine = (LPVOID)((BYTE*)ProcessParameters + 0x70);
        *(PUSHORT)((BYTE*)PCommandLine) = (USHORT)(Length * 2);
        *(PUSHORT)((BYTE*)PCommandLine + 2) = MaximumLength;
        *(PWSTR*)((BYTE*)PCommandLine + 8) = filePath;
        return state;
    }
    return state;
}

int main()
{
    WCHAR parentName[] = L"HONOR E.exe";
    if (!ParentProcessVerify(parentName)) {
        WCHAR filePath[MAX_PATH];
        GetModuleFileNameW(NULL, filePath, MAX_PATH);
        CreatProcessByParent(parentName, filePath);
        exit(-1);
    }
    if (ChangeProcessInformation(parentName)) {
        cout << "ok!" << endl;
    }
}