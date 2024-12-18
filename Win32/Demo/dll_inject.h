#pragma once
#include <Windows.h>
#include <iostream>
#ifdef _WIN64
typedef DWORD(WINAPI* PfnZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    ULONG CreateThreadFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximunStackSize,
    LPVOID pUnkown);
#else
typedef DWORD(WINAPI* PfnZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateThreadFlags,
    DWORD  ZeroBits,
    DWORD  StackSize,
    DWORD  MaximumStackSize,
    LPVOID pUnkown);
#endif
using namespace std;

typedef DWORD(WINAPI* pRtlCreateUserThread)(   
    IN HANDLE                     ProcessHandle,
    IN PSECURITY_DESCRIPTOR     SecurityDescriptor,
    IN BOOL                     CreateSuspended,
    IN ULONG                    StackZeroBits,
    IN OUT PULONG                StackReserved,
    IN OUT PULONG                StackCommit,
    IN LPVOID                    StartAddress,
    IN LPVOID                    StartParameter,
    OUT HANDLE                     ThreadHandle,
    OUT LPVOID                    ClientID
    );


FARPROC GetLoadLibraryAddress(HMODULE hModule);
FARPROC GetZwCreateThreadExAddress(HMODULE hModule);
FARPROC GetCreateUserThreadAddress(HMODULE hModule);
VOID WritePath(DWORD pid, WCHAR* szPath, HANDLE* lpProcess, LPVOID* lpRemoteAddress);
VOID CreateRemoteThreadInject(DWORD pid, WCHAR* szPath);
VOID NtCreateThreadExInject(DWORD pid, WCHAR* szPath);
VOID RtCreateUserThreadInject(DWORD pid, WCHAR* szPath);