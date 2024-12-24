#include "kernel.h"

#ifdef _WIN64
EXTERN_C HMODULE _cdecl KernelHandle();
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