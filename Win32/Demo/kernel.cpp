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
        xor eax, eax ; 初始化eax寄存器
        mov eax, fs: [eax + 30h] ; 32位fs寄存器存储TEB结构体的地址，TEB + 0x30 = PEB结构体的地址
        mov eax, [eax + 0ch]; PEB + 0x0c = PEB_LDR_DATA结构体的地址
        mov eax, [eax + 0ch]; PEB_LDR_DATA + 0x0c = InLoadOrderModuleList(Reserved2[1])的Flink字段, Flink字段指向LDR_DATA_TABLE_ENTRY结构体
        mov eax, [eax];跳过第一个链表(第一个是程序本身)，获取下一个链表的Flink字段
        mov eax, [eax]; 跳过第二个链表(第二个是ntdll.dll)，获取下一个链表的Flink字段
        mov eax, [eax + 18h]; LDR_DATA_TABLE_ENTRY + 0x18 = Kernel32.dll的地址
        mov ker32, eax;
    }
    return ker32;
#endif
}