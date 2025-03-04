//#include "util.h"
//#define SystemHandleInformation 0x10
//#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
//#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
//
//typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
//    USHORT UniqueProcessId; //句柄所属的进程PID
//    USHORT CreatorBackTraceIndex; //暂空
//    UCHAR ObjectTypeIndex; //
//    UCHAR HandleAttributes; //
//    USHORT HandleValue; //句柄的值
//    PVOID Object; //
//    ULONG GrantedAccess; //暂空
//} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
//
//typedef struct _SYSTEM_HANDLE_INFORMATION {
//    ULONG NumberOfHandles; //系统所有句柄的个数
//    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1]; //句柄信息数组
//} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
//
//typedef BOOL(WINAPI* PNtQuerySystemInformation)(
//    INT SystemInformationClass,
//    PVOID                    SystemInformation,
//    ULONG                    SystemInformationLength,
//    PULONG                   ReturnLength);
//
//typedef BOOL(WINAPI* PNtDuplicateObject)(
//    HANDLE      SourceProcessHandle,
//    HANDLE      SourceHandle,
//    HANDLE      TargetProcessHandle,
//    PHANDLE     TargetHandle,
//    ACCESS_MASK DesiredAccess,
//    ULONG       HandleAttributes,
//    ULONG       Options);
//
//typedef BOOL(WINAPI* PNtQueryObject)(
//    HANDLE                   Handle,
//    OBJECT_INFORMATION_CLASS ObjectInformationClass,
//    PVOID                    ObjectInformation,
//    ULONG                    ObjectInformationLength,
//    PULONG                   ReturnLength);
//
//
//int main(int argc, char* argv[]) {
//    DWORD targetPid = 21028;
//    ULONG returnLength = 0;
//    ULONG querySize = 0x1000;
//    PVOID queryBuff = NULL;
//    ULONG duplicateSize = 0x1000;
//    PVOID duplicateBuffer = NULL;
//    NTSTATUS status = 0;
//    HANDLE hDup = nullptr;
//    HMODULE hNtdll = GetModuleHandleA("ntdll");
//    if (hNtdll == NULL) {
//        cout << "load ntdll fail: " << GetLastError() << endl;
//        return 1;
//    }
//    PNtQuerySystemInformation _NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
//    PNtDuplicateObject _NtDuplicateObject = (PNtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");
//    PNtQueryObject _NtQueryObject = (PNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
//    if (_NtQuerySystemInformation == NULL || _NtDuplicateObject == NULL || _NtQueryObject == NULL) {
//        cout << "find function fail: " << GetLastError() << endl;
//        return 1;
//    }
//    do {
//        queryBuff = malloc(querySize);
//        status = _NtQuerySystemInformation(SystemHandleInformation, queryBuff, querySize, &returnLength);
//        if (!NT_SUCCESS(status))
//        {
//            if (STATUS_INFO_LENGTH_MISMATCH == status)
//            {
//                free(queryBuff);
//                queryBuff = NULL;
//                querySize = querySize * 2;
//                continue;
//            }
//            else
//            {
//                printf("ZwQuerySystemInformation() failed");
//                return 1;
//            }
//        }
//        else
//        {
//            break;
//        }
//    } while (true);
//    PSYSTEM_HANDLE_INFORMATION ptr = (PSYSTEM_HANDLE_INFORMATION)queryBuff;
//    ULONG NumberOfHandles = ptr->NumberOfHandles;
//    cout << "all handles " << NumberOfHandles << endl;
//    for (ULONG i = 0; i < NumberOfHandles; i++) {
//        SYSTEM_HANDLE_TABLE_ENTRY_INFO shtei = ptr->Handles[i];
//        if (shtei.UniqueProcessId != targetPid) {
//            continue;
//        }
//        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)shtei.UniqueProcessId);
//        if (!hProcess) {
//            continue;
//        }
//        status = _NtDuplicateObject(hProcess, (HANDLE)shtei.HandleValue, GetCurrentProcess(), &hDup, 0, 0, DUPLICATE_SAME_ACCESS);
//        if (!NT_SUCCESS(status)) {
//            cout << "error in NtDuplicateObject" << endl;
//            continue;
//        }
//        do {
//            duplicateBuffer = malloc(duplicateSize);
//            status = _NtQueryObject(hDup, ObjectTypeInformation, duplicateBuffer, duplicateSize, &returnLength);
//            if (!NT_SUCCESS(status))
//            {
//                if (STATUS_INFO_LENGTH_MISMATCH == status)
//                {
//                    free(duplicateBuffer);
//                    duplicateBuffer = NULL;
//                    duplicateSize = duplicateSize * 2;
//                    continue;
//                }
//                else
//                {
//                    printf("NtQuerySystemInformation() failed");
//                    return 1;
//                }
//            }
//            else
//            {
//                break;
//            }
//        } while (true);
//        PPUBLIC_OBJECT_TYPE_INFORMATION typeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)duplicateBuffer;
//        if (wcsicmp(typeInfo->TypeName.Buffer, L"Process") == 0) {
//            WCHAR imagePath[MAX_PATH];
//            DWORD dwSize = MAX_PATH;
//            QueryFullProcessImageNameW(hProcess, 0, imagePath, &dwSize);
//            wcout << imagePath << '\t';
//            cout << "Handle 0x" << hex << shtei.HandleValue << endl;
//        }
//        free(duplicateBuffer);
//        CloseHandle(hProcess);
//    }
//    free(queryBuff);
//    return 0;
//}