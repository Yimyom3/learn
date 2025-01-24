#include "Reflective.h"

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef LPVOID (WINAPI *PVirtualAlloc)(LPVOID,SIZE_T,DWORD,DWORD);

WCHAR ToLowerCaseW(WCHAR ch) {
	if (ch >= L'A' && ch <= L'Z') {
		return ch + (L'a' - L'A');
	}
	return ch;
}

WORD CompareStringW(PWSTR p1, PWSTR p2) {
	while (*p1 || *p2) {
		WCHAR lower_p1 = ToLowerCaseW(*p1);
		WCHAR lower_p2 = ToLowerCaseW(*p2);

		if (lower_p1 != lower_p2) {
			return lower_p1 - lower_p2;
		}
		++p1;
		++p2;
	}
	return 0;  
}

CHAR ToLowerCaseA(CHAR ch) {
	if (ch >= 'A' && ch <= 'Z') {
		return ch + ('a' - 'A');
	}
	return ch;
}

WORD CompareStringA(PSTR p1, PSTR p2) {
	while (*p1 || *p2) {
		CHAR lower_p1 = ToLowerCaseA(*p1);
		CHAR lower_p2 = ToLowerCaseA(*p2);

		if (lower_p1 != lower_p2) {
			return lower_p1 - lower_p2;
		}
		++p1;
		++p2;
	}
	return 0;
}

HANDLE GetImageBase() {
	PVOID funcAddress = _ReturnAddress();
	for (DWORD offset = 0;; offset++) {
		if (*((BYTE*)funcAddress - offset) == 0x5A) {
			if (*((BYTE*)funcAddress - (offset + 1)) == 0x4D) {
				LONG NToffset = *(PLONG)((BYTE*)funcAddress - offset + 0x3b) - 1;
				if (*(PDWORD)((BYTE*)funcAddress - offset + NToffset) == IMAGE_NT_SIGNATURE) {
					return (HANDLE)((BYTE*)funcAddress - (offset + 1));
				}
			}
		}
	}
}

HANDLE _GetModuleHandle(LPWSTR lpModuleName) {
#ifdef _WIN64
	LPVOID PPEB =(LPVOID)__readgsqword(0x60);
	LPVOID PPLD = *(LPVOID*)((BYTE*)PPEB + 0x18);
	LPVOID PILOML = *(LPVOID*)((BYTE*)PPLD + 0x10);
	while (PILOML) {
		UNICODE_STRING FullDllName = *(UNICODE_STRING*)((BYTE*)PILOML + 0x48);
		if (FullDllName.Length != 0) {
			if (CompareStringW(FullDllName.Buffer,lpModuleName) == 0) {
				return (HANDLE)(*(LPVOID*)((BYTE*)PILOML + 0x30));
			}
			PILOML = *(LPVOID*)PILOML;
		}
		else
		{
			break;
		}
	}
	return NULL;

#else
	LPVOID PPEB = NULL;
	__asm {
		mov eax, fs:[30h]
		mov PPEB, eax
	}
	if (PPEB == NULL) {
		return NULL;
	}
	LPVOID PPLD = *(LPVOID*)((BYTE*)PPEB + 0x0c);
	LPVOID PILOML = *(LPVOID*)((BYTE*)PPLD + 0x0c);
	while (PILOML) {
		UNICODE_STRING FullDllName = *(UNICODE_STRING*)((BYTE*)PILOML + 0x24);
		if (FullDllName.Length != 0) {
			if (CompareStringW(FullDllName.Buffer, lpModuleName) == 0) {
				return (HANDLE)(*(LPVOID*)((BYTE*)PILOML + 0x18));
			}
			PILOML = *(LPVOID*)PILOML;
		}
		else
		{
			break;
		}
	}
	return NULL;
#endif 
}

FARPROC _GetProcAddress(LPVOID hModule, LPSTR lpProcName) {
#ifdef _WIN64
	LPVOID pNt = ((BYTE*)hModule + (*(LONG*)((BYTE*)hModule + 0x3C)));
	LPVOID pExport = ((BYTE*)hModule + (*(LONG*)((BYTE*)pNt + 0x88)));
	DWORD Base = *(PDWORD)((BYTE*)pExport + 0x10);
	DWORD NumberOfFunctions = *(PDWORD)((BYTE*)pExport + 0x14);
	PDWORD pENT = (PDWORD)((BYTE*)hModule + (*(DWORD*)((BYTE*)pExport + 0x20)));
	PDWORD pEAT = (PDWORD)((BYTE*)hModule + (*(DWORD*)((BYTE*)pExport + 0x1C)));
	PDWORD pEIT = (PDWORD)((BYTE*)hModule + (*(DWORD*)((BYTE*)pExport + 0x24))); 
	for (Base;Base<=NumberOfFunctions;Base++) {
		if (CompareStringA((PSTR)((BYTE*)hModule + (*(pENT + Base))), lpProcName) == 0) {
			WORD index = (*(WORD*)((BYTE*)pEIT + (Base*2)));
			return (FARPROC)((BYTE*)hModule + (*(pEAT + index)));
		}
	}
	return NULL;
#else
	LPVOID pNt = ((BYTE*)hModule + (*(LONG*)((BYTE*)hModule + 0x3C)));
	LPVOID pExport = ((BYTE*)hModule + (*(LONG*)((BYTE*)pNt + 0x78)));
	DWORD Base = *(PDWORD)((BYTE*)pExport + 0x10);
	DWORD NumberOfFunctions = *(PDWORD)((BYTE*)pExport + 0x14);
	PDWORD pENT = (PDWORD)((BYTE*)hModule + (*(DWORD*)((BYTE*)pExport + 0x20)));
	PDWORD pEAT = (PDWORD)((BYTE*)hModule + (*(DWORD*)((BYTE*)pExport + 0x1C)));
	PDWORD pEIT = (PDWORD)((BYTE*)hModule + (*(DWORD*)((BYTE*)pExport + 0x24)));
	for (Base; Base <= NumberOfFunctions; Base++) {
		if (CompareStringA((PSTR)((BYTE*)hModule + (*(pENT + Base))), lpProcName) == 0) {
			WORD index = (*(WORD*)((BYTE*)pEIT + (Base * 2)));
			return (FARPROC)((BYTE*)hModule + (*(pEAT + index)));
		}
	}
	return NULL;
#endif
}

BOOL ApplyMemory(LPVOID* allocatedMemory) {
	WCHAR DllName[] = { L'c',L':',L'\\',L'w',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L's',L'y',L's',L't',L'e',L'm',L'3',L'2',L'\\',L'k',L'e',L'r',L'n',L'e',L'l',L'3',L'2',L'.',L'd',L'l',L'l' };
	CHAR funcName[] = { 'v','i','r','t','u','a','l','a','l','l','o','c' };
	HANDLE kernel32 = _GetModuleHandle(DllName);
	PVirtualAlloc _VirtualAlloc = (PVirtualAlloc)_GetProcAddress(kernel32, funcName);
	HANDLE PEImageBase = GetImageBase();
	LPVOID NTHead = ((BYTE*)PEImageBase + (*(PLONG)((BYTE*)PEImageBase + 0x3C)));
	SIZE_T size = *(PDWORD)((BYTE*)NTHead + 0x38);
	*allocatedMemory = _VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	return TRUE;
}

BOOL ReflectiveLoader() {
	
}