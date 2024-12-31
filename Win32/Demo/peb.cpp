#include "peb.h"

#ifdef _WIN64
EXTERN_C HMODULE _cdecl KernelHandle();
EXTERN_C HMODULE _cdecl NtHandle();
#endif

HMODULE GetKernelHandle() {
#ifdef _WIN64
	return KernelHandle();
#else
    HMODULE ker32;
    __asm {
        xor eax, eax ; ��ʼ��eax�Ĵ���
        mov eax, fs: [eax + 30h] ; 32λfs�Ĵ����洢TEB�ṹ��ĵ�ַ��TEB + 0x30 = PEB�ṹ��ĵ�ַ
        mov eax, [eax + 0ch]; PEB + 0x0c = PEB_LDR_DATA�ṹ��ĵ�ַ
        mov eax, [eax + 0ch]; PEB_LDR_DATA + 0x0c = InLoadOrderModuleList(Reserved2[1])��Flink�ֶ�, Flink�ֶ�ָ��LDR_DATA_TABLE_ENTRY�ṹ��
        mov eax, [eax];������һ������(��һ���ǳ�����)����ȡ��һ�������Flink�ֶ�
        mov eax, [eax]; �����ڶ�������(�ڶ�����ntdll.dll)����ȡ��һ�������Flink�ֶ�
        mov eax, [eax + 18h]; LDR_DATA_TABLE_ENTRY + 0x18 = Kernel32.dll�ĵ�ַ
        mov ker32, eax;
    }
    return ker32;
#endif
}

HMODULE GetNtHandle() {
#ifdef _WIN64
    return NtHandle();
#else
    HMODULE ker32;
    __asm {
        xor eax, eax; ��ʼ��eax�Ĵ���
        mov eax, fs: [eax + 30h] ; 32λfs�Ĵ����洢TEB�ṹ��ĵ�ַ��TEB + 0x30 = PEB�ṹ��ĵ�ַ
        mov eax, [eax + 0ch]; PEB + 0x0c = PEB_LDR_DATA�ṹ��ĵ�ַ
        mov eax, [eax + 0ch]; PEB_LDR_DATA + 0x0c = InLoadOrderModuleList(Reserved2[1])��Flink�ֶ�, Flink�ֶ�ָ��LDR_DATA_TABLE_ENTRY�ṹ��
        mov eax, [eax]; ������һ������(��һ���ǳ�����)����ȡ��һ�������Flink�ֶ�
        mov eax, [eax + 18h]; LDR_DATA_TABLE_ENTRY + 0x18 = ntdll.dll�ĵ�ַ
        mov ker32, eax;
    }
    return ker32;
#endif
}


FARPROC FindGetProcAddress(HMODULE ker32) {
#ifdef _WIN64
    if (ker32) {
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)ker32 + (*(LONG*)((BYTE*)ker32 + 0x3C)));
        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ker32 + (*(LONG*)((BYTE*)pNt + 0x88))); //��32λΨһ�������ǵ�����ƫ��������16�ֽ�
        PDWORD pENT = (PDWORD)((BYTE*)ker32 + (*(DWORD*)((BYTE*)pExport + 0x20)));  //�����������飬�����Ԫ�ش洢�ź������Ƶĵ�ַ
        PDWORD pEAT = (PDWORD)((BYTE*)ker32 + (*(DWORD*)((BYTE*)pExport + 0x1C))); //������ַ���飬�����Ԫ�ش洢�ź����ĵ�ַ����Ҫͨ�����������,������Ӧ���±�= ���-base����kernel32��baseΪ1��
        PDWORD pEIT = (PDWORD)((BYTE*)ker32 + (*(DWORD*)((BYTE*)pExport + 0x24))); //����������飬����洢�ź������ƶ�Ӧ������ַ����ţ�WORD���ͣ�
        /*
        ��ȡ˼·:
        1. ͨ���������������������ݣ���Ŀ�꺯�����Աȣ��õ��ú����ں�������������±�
        2. ������������ͺ���������鹲��һ���±꣬ͨ���±�õ�Ŀ�꺯���ں�����ַ�����е����
        3. ͨ������ں�����ַ������ȡ��Ŀ�꺯����ַ
        */
        for (int i = 0;; i++) {
            if (*(ULONG*)((BYTE*)ker32 + (*(pENT + i))) == 0x50746547UL) { 
                if (*(ULONG*)((BYTE*)ker32 + (*(pENT + i) + 4)) == 0x41636F72UL) { 
                    if (*(ULONG*)((BYTE*)ker32 + (*(pENT + i) + 8)) == 0x65726464UL) { 
                        WORD index = (*(WORD*)((BYTE*)pEIT + (i << 1))); 
                        return (FARPROC)((BYTE*)ker32 + (*(pEAT + index)));
                    }
                }
            }
        }
    }
#else
    if (ker32) {
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)ker32 + (*(LONG*)((BYTE*)ker32 + 0x3C)));
        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ker32 + (*(LONG*)((BYTE*)pNt + 0x78)));
        PDWORD pENT = (PDWORD)((BYTE*)ker32 + (*(DWORD*)((BYTE*)pExport + 0x20)));      
        PDWORD pEAT = (PDWORD)((BYTE*)ker32 + (*(DWORD*)((BYTE*)pExport + 0x1C))); 
        PDWORD pEIT = (PDWORD)((BYTE*)ker32 + (*(DWORD*)((BYTE*)pExport + 0x24)));                   
        for (int i = 0;; i++) {
            if (*(ULONG*)((BYTE*)ker32 + (*(pENT + i))) == 0x50746547UL) {
                if (*(ULONG*)((BYTE*)ker32 + (*(pENT + i) + 4)) == 0x41636F72UL) {
                    if (*(ULONG*)((BYTE*)ker32 + (*(pENT + i) + 8)) == 0x65726464UL) {
                        WORD index = (*(WORD*)((BYTE*)pEIT + (i << 1)));
                        return (FARPROC)((BYTE*)ker32 + (*(pEAT + index)));
                    }
                }
            }
        }
    }
#endif 
}