#include "syscall.h"
#include "peb.h"

typedef FARPROC(NTAPI* _GetProcAddress)(HMODULE hModule,LPCSTR lpProcName);


BOOL NTAPI GetSysCall(LPCSTR lpProcName, LPVOID* lp) {
    HMODULE NtModule = GetNtHandle();
    HMODULE KernelModulue = GetKernelHandle(); 
    _GetProcAddress GetProcAddressFunc = (_GetProcAddress)FindGetProcAddress(KernelModulue); 
    PUCHAR funcAddr = (PUCHAR)GetProcAddressFunc(NtModule, lpProcName); 
    WORD size;
#ifdef _WIN64
    if (*(PULONG)funcAddr == 0xB8D18B4C) {
        for (WORD i = 0; i < 50; i++) 
        {
            if (funcAddr[i] == 0xc3)
            {
                size = i + 1;
                *lp = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                memcpy(*lp, funcAddr,size);
                return TRUE;
            }
        }
        return FALSE;
    }
    return FALSE;

#else
    if (*funcAddr == 0xB8 && *(funcAddr+5) == 0xBA) {
        for (WORD i = 0; i < 50; i++)
        {
            if (funcAddr[i] == 0xc2)
            {
                size = i + 3;
                *lp = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                memcpy(*lp, funcAddr, size);
                return TRUE;
            }
        }
        return FALSE;
    }
    return FALSE;
#endif 
}