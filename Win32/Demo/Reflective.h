#pragma once
#include "pch.h"
#define EXTRACT_HIGH_4_BITS(word)(((word) & 0xF000) >> 12)
#define EXTRACT_LOW_12_BITS(word)((word) & 0x0FFF)
#ifdef _WIN64
#define IS_HIGHEST_BIT_SET(value)(((value) & 0x8000000000000000ULL) != 0)
#else
#define IS_HIGHEST_BIT_SET(value)(((value) & 0x80000000UL) != 0)
#endif

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef BOOL(WINAPI* PDllMain)(HINSTANCE, DWORD, LPVOID);
typedef LPVOID(WINAPI* PVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* PVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI* PLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI* PGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* PNtFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);

BOOL ReflectiveLoader();