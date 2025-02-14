#include "Reflective.h" 

/*
	1. 关闭编译器优化
	2. ReflectiveLoader函数只能使用局部变量
*/

WCHAR ToLowerCaseW(WCHAR ch) {
	if (ch >= L'A' && ch <= L'Z') {
		return ch + (L'a' - L'A');
	}
	return ch;
}

HANDLE GetPEAddress() {
	ULONG64 PEAddress = (ULONG64)GetPEAddress;
	while (TRUE) {
		if (*(PWORD)PEAddress == IMAGE_DOS_SIGNATURE) {
			if (*(PDWORD)((PBYTE)PEAddress + *(PLONG)((PBYTE)PEAddress + offsetof(IMAGE_DOS_HEADER, e_lfanew))) == IMAGE_NT_SIGNATURE) {
				return (HANDLE)PEAddress;
			}
		}
		PEAddress--;
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

DWORD ConvertSectionFlagsToProtect(DWORD characteristics) {
	switch (characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) {
	case IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ:
		return PAGE_EXECUTE_READ;
	case IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE:
		return PAGE_READWRITE;
	default:
		return PAGE_READONLY;
	}
}

HANDLE _GetModuleHandle(LPWSTR lpModuleName) {
#ifdef _WIN64
	LPVOID PPEB = (LPVOID)__readgsqword(offsetof(TEB, ProcessEnvironmentBlock)); //PEB指针
	LPVOID PPLD = *(LPVOID*)((BYTE*)PPEB + offsetof(PEB, Ldr)); //LDR指针
	LPVOID PILOML = *(LPVOID*)((BYTE*)PPLD + offsetof(PEB_LDR_DATA, Reserved2[1])); //InLoadOrderModuleList链表的Flink指针
	while (PILOML) {
		UNICODE_STRING fullDllName = *(UNICODE_STRING*)((BYTE*)PILOML + offsetof(LDR_DATA_TABLE_ENTRY, FullDllName));
		if (fullDllName.Length != 0) {
			if (CompareStringW(fullDllName.Buffer, lpModuleName) == 0) {
				return (HANDLE)(*(LPVOID*)((BYTE*)PILOML + offsetof(LDR_DATA_TABLE_ENTRY, DllBase)));
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
		mov eax, fs: [30h]
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
	LPVOID pNt = ((BYTE*)hModule + (*(LONG*)((BYTE*)hModule + offsetof(IMAGE_DOS_HEADER, e_lfanew))));
	LPVOID pExport = ((BYTE*)hModule + (*(LONG*)((BYTE*)pNt + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory[0])))); //函数导出表目录
	DWORD base = *(PDWORD)((BYTE*)pExport + offsetof(IMAGE_EXPORT_DIRECTORY, Base)); //函数序号基数
	DWORD numberOfFunctions = *(PDWORD)((BYTE*)pExport + offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfFunctions));
	PDWORD pEAT = (PDWORD)((BYTE*)hModule + (*(DWORD*)((BYTE*)pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfFunctions)))); //函数地址数组指针
	PDWORD pENT = (PDWORD)((BYTE*)hModule + (*(DWORD*)((BYTE*)pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNames)))); //函数名称数组指针
	PDWORD pEIT = (PDWORD)((BYTE*)hModule + (*(DWORD*)((BYTE*)pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals)))); //函数序号数组指针
	for (base; base <= numberOfFunctions; base++) {
		if (CompareStringA((PSTR)((BYTE*)hModule + (*(pENT + base))), lpProcName) == 0) {
			WORD index = (*(WORD*)((BYTE*)pEIT + (base * 2)));
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


extern "C" DllExport BOOL ReflectiveLoader() {

	/*
		1.定义变量: 要用到的DLL和函数名称、函数指针
	*/
	WCHAR kernel32[] = { L'c',L':',L'\\',L'w',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L's',L'y',L's',L't',L'e',L'm',L'3',L'2',L'\\',L'k',L'e',L'r',L'n',L'e',L'l',L'3',L'2',L'.',L'd',L'l',L'l',L'\0' };
	CHAR virtualAlloc[] = { 'v','i','r','t','u','a','l','a','l','l','o','c','\0' };
	CHAR virtualProtect[] = { 'v','i','r','t','u','a','l','p','r','o','t','e','c','t','\0' };
	CHAR loadLibraryA[] = { 'l','o','a','d','l','i','b','r','a','r','y','a','\0' };
	CHAR getProcAddress[] = { 'g','e','t','p','r','o','c','a','d','d','r','e','s','s','\0' };
	CHAR flushInstructionCache[] = {'f','l','u','s','h','i','n','s','t','r','u','c','t','i','o','n','c','a','c','h','e','\0' };
	HANDLE hKernel32 = _GetModuleHandle(kernel32);
	if ((hKernel32) == NULL) {
		return FALSE;
	}
	PVirtualAlloc _VirtualAlloc = (PVirtualAlloc)_GetProcAddress(hKernel32, virtualAlloc);
	if (_VirtualAlloc == NULL) {
		return FALSE;
	}
	PVirtualProtect _VirtualProtect = (PVirtualProtect)_GetProcAddress(hKernel32, virtualProtect);
	if (_VirtualProtect == NULL) {
		return FALSE;
	}
	PLoadLibraryA _LoadLibraryA = (PLoadLibraryA)_GetProcAddress(hKernel32, loadLibraryA);
	if (_LoadLibraryA == NULL) {
		return FALSE;
	}
	PGetProcAddress __GetProcAddress = (PGetProcAddress)_GetProcAddress(hKernel32, getProcAddress);
	if (__GetProcAddress == NULL) {
		return FALSE;
	}
	PFlushInstructionCache _FlushInstructionCache = (PFlushInstructionCache)_GetProcAddress(hKernel32, flushInstructionCache);
	if (_FlushInstructionCache == NULL) {
		return FALSE;
	}

	/*
		2.解析PE文件，获取关键信息
	*/
	LPVOID PEAddress = GetPEAddress(); //PE基址
	LPVOID NTHeaders = ((BYTE*)PEAddress + *(PLONG)((BYTE*)PEAddress + offsetof(IMAGE_DOS_HEADER, e_lfanew))); //NT头
	LPVOID NTOptionHeader = ((BYTE*)NTHeaders + offsetof(IMAGE_NT_HEADERS, OptionalHeader)); //NT拓展头
	DWORD addressOfEntryPoint = *(PDWORD)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint)); //程序入口地址RVA
	ULONG64 addressOfEntryPointOffset = (ULONG64)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint)) - (ULONG64)PEAddress; //程序入口地址偏移量
	ULONG64 ImageBaseOffset = (ULONG64)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase)) - (ULONG64)PEAddress; //ImageBase的偏移量
	ULONG64 imageBase = *(PULONG64)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase)); //PE中默认映象基址
	DWORD sectionAlignment = *(PDWORD)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, SectionAlignment)); //内存对齐大小
	DWORD fileAlignment = *(PDWORD)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, FileAlignment)); //磁盘对齐大小
	DWORD sizeOfImage = *(PDWORD)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage)); //映象文件总大小
	DWORD sizeOfHeaders = *(PDWORD)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders)); //PE头总大小
	WORD NumberOfSections = *(PWORD)((BYTE*)NTHeaders + 6); //节的数量
	LPVOID PImageSectionHeader = ((BYTE*)NTOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER64)); //节表指针

	/*
		3.申请内存空间，把PE文件内容复制
	*/
	LPVOID DLLHandle = _VirtualAlloc(NULL, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); //申请内存得到DLL句柄
	if (DLLHandle == NULL) {
		return FALSE;
	}
	for (DWORD i = 0; i < sizeOfHeaders; i++) {
		*((BYTE*)DLLHandle + i) = *((BYTE*)PEAddress + i); //先把PE头复制过去
	}
	*(PULONG64)((BYTE*)DLLHandle + ImageBaseOffset) = (ULONG64)DLLHandle; //修正映象基址
	for (WORD i = 0; i < NumberOfSections; i++) {  //复制每个节
		DWORD virtualAddress = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, VirtualAddress)); //内存中节的RVA
		DWORD sizeOfRawData = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, SizeOfRawData)); //节在磁盘上的大小(对齐后)
		DWORD pointerToRawData = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, PointerToRawData)); //磁盘中节的RVA
		DWORD OldProtect = 0;
		for (DWORD j = 0; j < sizeOfRawData; j++) {
			*((BYTE*)DLLHandle + virtualAddress + j) = *((BYTE*)PEAddress + pointerToRawData + j); //复制节的内容
		}
	}

	/*
		4.修复导入表(IAT)
	*/
	LPVOID PImageImportDescriptor = ((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory[1])); //导入目录表
	DWORD ImageImportDescriptorVirtualAddress = *(PDWORD)PImageImportDescriptor; //导入表RVA
	DWORD ImageImportDescriptorSize = *((PDWORD)PImageImportDescriptor + 1); //导入表大小
	DWORD DLLcount = (ImageImportDescriptorSize / sizeof(IMAGE_IMPORT_DESCRIPTOR)) - 1; //需要导入DLL的数量
	LPVOID PImageImport = ((BYTE*)DLLHandle + ImageImportDescriptorVirtualAddress); //实际导入表地址
	for (DWORD i = 0; i < DLLcount; i++) {
		DWORD NameRVA = *(PDWORD)((BYTE*)PImageImport + i * sizeof(IMAGE_IMPORT_DESCRIPTOR) + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)); //函数名称的RVA
		LPSTR DLLName = (LPSTR)((BYTE*)DLLHandle + NameRVA); //获取DLL名称
		if ((ULONG64)((PVOID)DLLName) < 0x10000) { //DLL名称检查
			return FALSE;
		}
		HMODULE DLLHmodule = _LoadLibraryA(DLLName);//加载DLL
		if (DLLHmodule == NULL) {
			return FALSE;
		}
		DWORD FirstThunk = *(PDWORD)((BYTE*)PImageImport + i * sizeof(IMAGE_IMPORT_DESCRIPTOR) + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)); //获取导入函数表(IAT)RVA
		DWORD OriginalFirstThunk = *(PDWORD)((BYTE*)PImageImport + i * sizeof(IMAGE_IMPORT_DESCRIPTOR) + offsetof(IMAGE_IMPORT_DESCRIPTOR, OriginalFirstThunk)); //获取INT表RVA
		LPVOID PIAT = ((BYTE*)DLLHandle + FirstThunk); //IAT表的地址 3078
		LPVOID PINT = ((BYTE*)DLLHandle + OriginalFirstThunk); //INT表的地址 3bb8
		for (DWORD j = 0;; j++) {
			if (*((PULONG64)PIAT + j) == 0) {
				break;
			}
			if (IS_HIGHEST_BIT_SET(*((PULONG64)PINT + j))) { //如果最高位为1，则表示函数的序号
				WORD ordinal = *(PWORD)((PULONG64)PINT + j);
				FARPROC funcAddress = __GetProcAddress(DLLHmodule, (LPCSTR)ordinal); //通过序号获取函数地址
				if (funcAddress == NULL) {
					return FALSE;
				}
				*((PULONG64)PIAT + j) = (ULONG64)funcAddress; //修复IAT表的地址
			}
			else //如果最高位为0，则表示是IMAGE_IMPORT_BY_NAME的RVA
			{
				ULONG64 ImageThunkRVA = *((PULONG64)PINT + j);
				LPCSTR funcName = (LPCSTR)((BYTE*)DLLHandle + ImageThunkRVA + 2); //函数名称
				if ((ULONG64)((PVOID)funcName) < 0x10000) { //函数名称检查
					return FALSE;
				}
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
	LPVOID PImageBaseRelocation = ((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory[5])); //重定位目录表指针
	DWORD ImageBaseRelocationVirtualAddress = *(PDWORD)PImageBaseRelocation; //重定位表RVA
	DWORD ImageBaseRelocationSize = *((PDWORD)PImageBaseRelocation + 1); //重定位表大小
	ULONG64 Difference = (ULONG64)DLLHandle - imageBase; //计算映象地址差值
	LPVOID RelocationAddress = ((BYTE*)DLLHandle + ImageBaseRelocationVirtualAddress);  //重定位表地址
	DWORD UsedSize = 0; //已使用重定位表大小
	do {
		RelocationAddress = (BYTE*)(RelocationAddress)+UsedSize;
		LPVOID ActualAddress = ((BYTE*)DLLHandle + *(PDWORD)RelocationAddress); //实际要重定位的地址
		DWORD RelocationCount = (*((PDWORD)RelocationAddress + 1) - sizeof(IMAGE_BASE_RELOCATION)) / 2; //要重定位地址的数量
		for (DWORD i = 0; i < RelocationCount; i++) {
			DWORD Offset = (DWORD)EXTRACT_LOW_12_BITS(*((PWORD)((BYTE*)RelocationAddress + sizeof(IMAGE_BASE_RELOCATION)) + i));//提取低12位得到重定位地址偏移量
			if (Offset == 0) {
				continue;
			}
			*(PULONG64)((BYTE*)ActualAddress + Offset) += Difference; //修正地址为重定位地址
		}
		UsedSize += *((PDWORD)RelocationAddress + 1);
	} while (ImageBaseRelocationSize > UsedSize);

	/*
		6.为节分配正确的内存属性
		  放到第6步是因为中间要修复导入表和重定位表
	*/
	for (WORD i = 0; i < NumberOfSections; i++) {  //复制每个节
		DWORD virtualAddress = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, VirtualAddress)); //内存中节的RVA
		DWORD sizeOfRawData = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, SizeOfRawData)); //节在磁盘上的大小(对齐后)
		DWORD virtualSize = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, Misc.VirtualSize)); //节在内存中的大小(对齐前)
		DWORD characteristics = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, Characteristics)); //节在PE中的内存属性
		DWORD OldProtect = 0;
		if (ALIGN_VIRTUAL_SIZE(virtualSize, sectionAlignment) != 0) {
			if (!_VirtualProtect(((BYTE*)DLLHandle + virtualAddress), ALIGN_VIRTUAL_SIZE(virtualSize, sectionAlignment), ConvertSectionFlagsToProtect(characteristics), &OldProtect)) { //为节分配属性
				return FALSE;
			}
		}
	}

	/*
		7.调用DLL入口函数
	*/
	if (_FlushInstructionCache((HANDLE)-1, NULL, NULL) == NULL) { //刷新当前进程的指令缓存，不能用NtFlushInstructionCache,不知道为什么,很奇怪
		return FALSE; 
	}
	PDllMain _DllMain = (PDllMain)((BYTE*)DLLHandle + addressOfEntryPoint); //DLL入口函数指针
	return _DllMain((HINSTANCE)DLLHandle, DLL_PROCESS_ATTACH, NULL); //转到DLL入口函数开始执行
}