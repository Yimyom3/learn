#include "peb.h"

#ifdef _WIN64
EXTERN_C HMODULE _cdecl KernelHandle();
EXTERN_C HMODULE _cdecl NtHandle();
EXTERN_C VOID _cdecl RunCalc();
#endif

HMODULE GetKernelHandle() {
#ifdef _WIN64
	return KernelHandle();
#else
    HMODULE ker32;
    __asm {
        mov eax, fs: [30h] ; 32位fs寄存器存储TEB结构体的地址，TEB + 0x30 = PEB结构体的地址
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

HMODULE GetNtHandle() {
#ifdef _WIN64
    return NtHandle();
#else
    HMODULE ker32;
    __asm {
        mov eax, fs: [30h] ; 32位fs寄存器存储TEB结构体的地址，TEB + 0x30 = PEB结构体的地址
        mov eax, [eax + 0ch]; PEB + 0x0c = PEB_LDR_DATA结构体的地址
        mov eax, [eax + 0ch]; PEB_LDR_DATA + 0x0c = InLoadOrderModuleList(Reserved2[1])的Flink字段, Flink字段指向LDR_DATA_TABLE_ENTRY结构体
        mov eax, [eax]; 跳过第一个链表(第一个是程序本身)，获取下一个链表的Flink字段
        mov eax, [eax + 18h]; LDR_DATA_TABLE_ENTRY + 0x18 = ntdll.dll的地址
        mov ker32, eax;
    }
    return ker32;
#endif
}


FARPROC FindGetProcAddress(HMODULE ker32) {
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

VOID calc() {
#ifdef _WIN64
    //BYTE shellcode[] = { "\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x48\x8B\x40\x18\x48\x8B\x40\x10\x48\x8B\x00\x48\x8B\x00\x48\x8B\x78\x30\x8B\x57\x3C\x48\x03\xD7\x8B\xB2\x88\x00\x00\x00\x48\x03\xF7\x48\x33\xC9\x8B\x56\x20\x48\x03\xD7\x8B\x04\x8A\x48\x03\xC7\x49\xB9\x57\x69\x6E\x45\x78\x65\x63\x00\x4C\x39\x08\x75\x18\x8B\x56\x24\x48\x03\xD7\x66\x8B\x0C\x4A\x8B\x56\x1C\x48\x03\xD7\x8B\x14\x8A\x48\x03\xFA\xEB\x08\x48\xFF\xC1\x3B\x4E\x14\x7C\xC5\x48\x8B\x1C\x24\x48\x83\xEC\x08\xC7\x04\x24\x63\x61\x6C\x63\xC6\x44\x24\x04\x00\xBA\x01\x00\x00\x00\x48\x8D\x0C\x24\xFF\xD7\x48\x83\xC4\x08\x48\x89\x1C\x24\xC3" };
    return RunCalc();
#else
    /*
    1. eax -> 临时地址
    2. ebx -> kernel32地址
    3. edx -> 偏移量地址
    4. esi -> 导出表地址
    5. ecx -> 计数器
    BYTE shellcode[] = { "\x55\x8B\xEC\x53\x56\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C\x8B\x40\x0C\x8B\x00\x8B\x00\x8B\x58\x18\x8B\x53\x3C\x03\xD3\x8B\x72\x78\x03\xF3\x33\xC9\x8B\x56\x20\x03\xD3\x8B\x04\x8A\x03\xC3\x81\x38\x57\x69\x6E\x45\x75\x1E\x81\x78\x04\x78\x65\x63\x00\x75\x15\x8B\x56\x24\x03\xD3\x66\x8B\x0C\x4A\x8B\x56\x1C\x03\xD3\x8B\x14\x8A\x03\xDA\xEB\x06\x41\x3B\x4E\x14\x7C\xCA\x83\xEC\x08\xC6\x45\xF8\x63\xC6\x45\xF9\x61\xC6\x45\xFA\x6C\xC6\x45\xFB\x63\xC6\x45\xFC\x00\x6A\x01\x8D\x45\xF8\x50\xFF\xD3\x83\xC4\x08\x5E\x5B\x5D\xC3" };
    */ 
    _asm {
        mov eax, fs: [30h]
        mov eax, [eax + 0ch]
        mov eax, [eax + 0ch]
        mov eax, [eax]
        mov eax, [eax]
        mov ebx, [eax + 18h]; Kernel32
        mov edx, [ebx + 3ch]; pNT
        add edx, ebx;NT偏移量
        mov esi, [edx + 78h]
        add esi, ebx
        xor ecx, ecx; 从这里开始进入循环
        find_function :
        mov edx, [esi + 20h]
            add edx, ebx
            mov eax, [edx + ecx * 4]
            add eax, ebx
            cmp dword ptr[eax], 456E6957h
            jne not_found
            cmp dword ptr[eax + 4], 00636578h
            jne not_found
            mov edx, [esi + 24h]
            add edx, ebx
            mov cx, word ptr[edx + ecx * 2]
            mov edx, [esi + 1ch]
            add edx, ebx
            mov edx, [edx + ecx * 4]
            add ebx, edx
            jmp end_search
            not_found :
        inc ecx
            cmp ecx, [esi + 14h]; 函数数量
            jl find_function
        end_search :
            sub esp, 8
            mov BYTE PTR [ebp - 8], 99
            mov BYTE PTR [ebp - 7], 97
            mov BYTE PTR [ebp - 6], 108
            mov BYTE PTR [ebp - 5], 99
            mov BYTE PTR [ebp - 4], 0
            push 1
            lea eax, DWORD PTR [ebp-8]
            push eax
            call ebx
            add esp,8
    };
#endif 
}