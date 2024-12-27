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

FARPROC _GetProcAddress(HMODULE ker32) {
#ifdef _WIN64
    if (ker32) {
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)ker32 + (*(LONG*)((BYTE*)ker32 + 0x3C)));
        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ker32 + (*(LONG*)((BYTE*)pNt + 0x88))); //和32位唯一的区别是导出表偏移量多了16字节
        PDWORD pENT = (PDWORD)((BYTE*)ker32 + (*(DWORD*)((BYTE*)pExport + 0x20)));  //函数名称数组，里面的元素存储着函数名称的地址
        PDWORD pEAT = (PDWORD)((BYTE*)ker32 + (*(DWORD*)((BYTE*)pExport + 0x1C))); //函数地址数组，里面的元素存储着函数的地址，需要通过序号来查找,函数对应的下标= 序号-base（在kernel32中base为1）
        PDWORD pEIT = (PDWORD)((BYTE*)ker32 + (*(DWORD*)((BYTE*)pExport + 0x24))); //函数序号数组，里面存储着函数名称对应函数地址的序号（WORD类型）
        /*
        获取思路:
        1. 通过遍历函数名称数组内容，和目标函数名对比，得到该函数在函数名称数组的下标
        2. 函数名称数组和函数序号数组共享一个下标，通过下标得到目标函数在函数地址数组中的序号
        3. 通过序号在函数地址数组中取得目标函数地址
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
