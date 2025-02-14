#include "Reflective.h" 

/*
	1. �رձ������Ż�
	2. ReflectiveLoader����ֻ��ʹ�þֲ�����
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
	LPVOID PPEB = (LPVOID)__readgsqword(offsetof(TEB, ProcessEnvironmentBlock)); //PEBָ��
	LPVOID PPLD = *(LPVOID*)((BYTE*)PPEB + offsetof(PEB, Ldr)); //LDRָ��
	LPVOID PILOML = *(LPVOID*)((BYTE*)PPLD + offsetof(PEB_LDR_DATA, Reserved2[1])); //InLoadOrderModuleList�����Flinkָ��
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
	LPVOID pExport = ((BYTE*)hModule + (*(LONG*)((BYTE*)pNt + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory[0])))); //����������Ŀ¼
	DWORD base = *(PDWORD)((BYTE*)pExport + offsetof(IMAGE_EXPORT_DIRECTORY, Base)); //������Ż���
	DWORD numberOfFunctions = *(PDWORD)((BYTE*)pExport + offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfFunctions));
	PDWORD pEAT = (PDWORD)((BYTE*)hModule + (*(DWORD*)((BYTE*)pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfFunctions)))); //������ַ����ָ��
	PDWORD pENT = (PDWORD)((BYTE*)hModule + (*(DWORD*)((BYTE*)pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNames)))); //������������ָ��
	PDWORD pEIT = (PDWORD)((BYTE*)hModule + (*(DWORD*)((BYTE*)pExport + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals)))); //�����������ָ��
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
		1.�������: Ҫ�õ���DLL�ͺ������ơ�����ָ��
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
		2.����PE�ļ�����ȡ�ؼ���Ϣ
	*/
	LPVOID PEAddress = GetPEAddress(); //PE��ַ
	LPVOID NTHeaders = ((BYTE*)PEAddress + *(PLONG)((BYTE*)PEAddress + offsetof(IMAGE_DOS_HEADER, e_lfanew))); //NTͷ
	LPVOID NTOptionHeader = ((BYTE*)NTHeaders + offsetof(IMAGE_NT_HEADERS, OptionalHeader)); //NT��չͷ
	DWORD addressOfEntryPoint = *(PDWORD)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint)); //������ڵ�ַRVA
	ULONG64 addressOfEntryPointOffset = (ULONG64)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint)) - (ULONG64)PEAddress; //������ڵ�ַƫ����
	ULONG64 ImageBaseOffset = (ULONG64)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase)) - (ULONG64)PEAddress; //ImageBase��ƫ����
	ULONG64 imageBase = *(PULONG64)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase)); //PE��Ĭ��ӳ���ַ
	DWORD sectionAlignment = *(PDWORD)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, SectionAlignment)); //�ڴ�����С
	DWORD fileAlignment = *(PDWORD)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, FileAlignment)); //���̶����С
	DWORD sizeOfImage = *(PDWORD)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage)); //ӳ���ļ��ܴ�С
	DWORD sizeOfHeaders = *(PDWORD)((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders)); //PEͷ�ܴ�С
	WORD NumberOfSections = *(PWORD)((BYTE*)NTHeaders + 6); //�ڵ�����
	LPVOID PImageSectionHeader = ((BYTE*)NTOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER64)); //�ڱ�ָ��

	/*
		3.�����ڴ�ռ䣬��PE�ļ����ݸ���
	*/
	LPVOID DLLHandle = _VirtualAlloc(NULL, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); //�����ڴ�õ�DLL���
	if (DLLHandle == NULL) {
		return FALSE;
	}
	for (DWORD i = 0; i < sizeOfHeaders; i++) {
		*((BYTE*)DLLHandle + i) = *((BYTE*)PEAddress + i); //�Ȱ�PEͷ���ƹ�ȥ
	}
	*(PULONG64)((BYTE*)DLLHandle + ImageBaseOffset) = (ULONG64)DLLHandle; //����ӳ���ַ
	for (WORD i = 0; i < NumberOfSections; i++) {  //����ÿ����
		DWORD virtualAddress = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, VirtualAddress)); //�ڴ��нڵ�RVA
		DWORD sizeOfRawData = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, SizeOfRawData)); //���ڴ����ϵĴ�С(�����)
		DWORD pointerToRawData = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, PointerToRawData)); //�����нڵ�RVA
		DWORD OldProtect = 0;
		for (DWORD j = 0; j < sizeOfRawData; j++) {
			*((BYTE*)DLLHandle + virtualAddress + j) = *((BYTE*)PEAddress + pointerToRawData + j); //���ƽڵ�����
		}
	}

	/*
		4.�޸������(IAT)
	*/
	LPVOID PImageImportDescriptor = ((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory[1])); //����Ŀ¼��
	DWORD ImageImportDescriptorVirtualAddress = *(PDWORD)PImageImportDescriptor; //�����RVA
	DWORD ImageImportDescriptorSize = *((PDWORD)PImageImportDescriptor + 1); //������С
	DWORD DLLcount = (ImageImportDescriptorSize / sizeof(IMAGE_IMPORT_DESCRIPTOR)) - 1; //��Ҫ����DLL������
	LPVOID PImageImport = ((BYTE*)DLLHandle + ImageImportDescriptorVirtualAddress); //ʵ�ʵ�����ַ
	for (DWORD i = 0; i < DLLcount; i++) {
		DWORD NameRVA = *(PDWORD)((BYTE*)PImageImport + i * sizeof(IMAGE_IMPORT_DESCRIPTOR) + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)); //�������Ƶ�RVA
		LPSTR DLLName = (LPSTR)((BYTE*)DLLHandle + NameRVA); //��ȡDLL����
		if ((ULONG64)((PVOID)DLLName) < 0x10000) { //DLL���Ƽ��
			return FALSE;
		}
		HMODULE DLLHmodule = _LoadLibraryA(DLLName);//����DLL
		if (DLLHmodule == NULL) {
			return FALSE;
		}
		DWORD FirstThunk = *(PDWORD)((BYTE*)PImageImport + i * sizeof(IMAGE_IMPORT_DESCRIPTOR) + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)); //��ȡ���뺯����(IAT)RVA
		DWORD OriginalFirstThunk = *(PDWORD)((BYTE*)PImageImport + i * sizeof(IMAGE_IMPORT_DESCRIPTOR) + offsetof(IMAGE_IMPORT_DESCRIPTOR, OriginalFirstThunk)); //��ȡINT��RVA
		LPVOID PIAT = ((BYTE*)DLLHandle + FirstThunk); //IAT��ĵ�ַ 3078
		LPVOID PINT = ((BYTE*)DLLHandle + OriginalFirstThunk); //INT��ĵ�ַ 3bb8
		for (DWORD j = 0;; j++) {
			if (*((PULONG64)PIAT + j) == 0) {
				break;
			}
			if (IS_HIGHEST_BIT_SET(*((PULONG64)PINT + j))) { //������λΪ1�����ʾ���������
				WORD ordinal = *(PWORD)((PULONG64)PINT + j);
				FARPROC funcAddress = __GetProcAddress(DLLHmodule, (LPCSTR)ordinal); //ͨ����Ż�ȡ������ַ
				if (funcAddress == NULL) {
					return FALSE;
				}
				*((PULONG64)PIAT + j) = (ULONG64)funcAddress; //�޸�IAT��ĵ�ַ
			}
			else //������λΪ0�����ʾ��IMAGE_IMPORT_BY_NAME��RVA
			{
				ULONG64 ImageThunkRVA = *((PULONG64)PINT + j);
				LPCSTR funcName = (LPCSTR)((BYTE*)DLLHandle + ImageThunkRVA + 2); //��������
				if ((ULONG64)((PVOID)funcName) < 0x10000) { //�������Ƽ��
					return FALSE;
				}
				FARPROC funcAddress = __GetProcAddress(DLLHmodule, funcName); //ͨ���������ƻ�ȡ������ַ
				if (funcAddress == NULL) {
					return FALSE;
				}
				*((PULONG64)PIAT + j) = (ULONG64)funcAddress; //�޸�IAT��ĵ�ַ
			}
		}
	}

	/*
		5.�޸��ض�λ��
	*/
	LPVOID PImageBaseRelocation = ((BYTE*)NTOptionHeader + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory[5])); //�ض�λĿ¼��ָ��
	DWORD ImageBaseRelocationVirtualAddress = *(PDWORD)PImageBaseRelocation; //�ض�λ��RVA
	DWORD ImageBaseRelocationSize = *((PDWORD)PImageBaseRelocation + 1); //�ض�λ���С
	ULONG64 Difference = (ULONG64)DLLHandle - imageBase; //����ӳ���ַ��ֵ
	LPVOID RelocationAddress = ((BYTE*)DLLHandle + ImageBaseRelocationVirtualAddress);  //�ض�λ���ַ
	DWORD UsedSize = 0; //��ʹ���ض�λ���С
	do {
		RelocationAddress = (BYTE*)(RelocationAddress)+UsedSize;
		LPVOID ActualAddress = ((BYTE*)DLLHandle + *(PDWORD)RelocationAddress); //ʵ��Ҫ�ض�λ�ĵ�ַ
		DWORD RelocationCount = (*((PDWORD)RelocationAddress + 1) - sizeof(IMAGE_BASE_RELOCATION)) / 2; //Ҫ�ض�λ��ַ������
		for (DWORD i = 0; i < RelocationCount; i++) {
			DWORD Offset = (DWORD)EXTRACT_LOW_12_BITS(*((PWORD)((BYTE*)RelocationAddress + sizeof(IMAGE_BASE_RELOCATION)) + i));//��ȡ��12λ�õ��ض�λ��ַƫ����
			if (Offset == 0) {
				continue;
			}
			*(PULONG64)((BYTE*)ActualAddress + Offset) += Difference; //������ַΪ�ض�λ��ַ
		}
		UsedSize += *((PDWORD)RelocationAddress + 1);
	} while (ImageBaseRelocationSize > UsedSize);

	/*
		6.Ϊ�ڷ�����ȷ���ڴ�����
		  �ŵ���6������Ϊ�м�Ҫ�޸��������ض�λ��
	*/
	for (WORD i = 0; i < NumberOfSections; i++) {  //����ÿ����
		DWORD virtualAddress = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, VirtualAddress)); //�ڴ��нڵ�RVA
		DWORD sizeOfRawData = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, SizeOfRawData)); //���ڴ����ϵĴ�С(�����)
		DWORD virtualSize = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, Misc.VirtualSize)); //�����ڴ��еĴ�С(����ǰ)
		DWORD characteristics = *(PDWORD)((BYTE*)PImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER) + offsetof(IMAGE_SECTION_HEADER, Characteristics)); //����PE�е��ڴ�����
		DWORD OldProtect = 0;
		if (ALIGN_VIRTUAL_SIZE(virtualSize, sectionAlignment) != 0) {
			if (!_VirtualProtect(((BYTE*)DLLHandle + virtualAddress), ALIGN_VIRTUAL_SIZE(virtualSize, sectionAlignment), ConvertSectionFlagsToProtect(characteristics), &OldProtect)) { //Ϊ�ڷ�������
				return FALSE;
			}
		}
	}

	/*
		7.����DLL��ں���
	*/
	if (_FlushInstructionCache((HANDLE)-1, NULL, NULL) == NULL) { //ˢ�µ�ǰ���̵�ָ��棬������NtFlushInstructionCache,��֪��Ϊʲô,�����
		return FALSE; 
	}
	PDllMain _DllMain = (PDllMain)((BYTE*)DLLHandle + addressOfEntryPoint); //DLL��ں���ָ��
	return _DllMain((HINSTANCE)DLLHandle, DLL_PROCESS_ATTACH, NULL); //ת��DLL��ں�����ʼִ��
}