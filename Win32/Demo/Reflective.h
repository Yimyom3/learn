#pragma once
#include<intrin.h>
#include <windows.h>
#include <winternl.h>
#include <iostream>
#define WIN32_LEAN_AND_MEAN
#define DllExport   __declspec( dllexport )
#define EXTRACT_HIGH_4_BITS(word)(((word) & 0xF000) >> 12)
#define EXTRACT_LOW_12_BITS(word)((word) & 0x0FFF)
#define ALIGN_VIRTUAL_SIZE(v,p)(((v) == 0) ? 0 : (((v) - 1) | (p - 1)) + 1)
#ifdef _WIN64
#define IS_HIGHEST_BIT_SET(value)(((value) & 0x8000000000000000ULL) != 0)
#else
#define IS_HIGHEST_BIT_SET(value)(((value) & 0x80000000UL) != 0)
#endif

using namespace std;

typedef struct _BASE_RELOCATION_ENTRY {
	WORD	Offset : 12;
	WORD	Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef BOOL(WINAPI* PDllMain)(HINSTANCE, DWORD, LPVOID);
typedef LPVOID(WINAPI* PVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* PVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI* PLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI* PGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* PNTFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);