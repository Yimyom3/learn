#include "pch.h"

LPVOID Getg_CiOptionsAddress() {
    LPVOID PCiInitialize = NULL;
    LPVOID PCipInitialize = NULL;
    LPVOID Pg_CiOptions = NULL;
    LPVOID PNtg_CiOptions = NULL;
    PBYTE ptr = NULL;
    ULONG_PTR offset = 0;
    LPVOID drivers[1024];
    DWORD cbNeeded, cDrivers = 0;
    HMODULE hModule = NULL;
    hModule = LoadLibraryExA("ci.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hModule == NULL) {
        return NULL;
    }
    PCiInitialize = GetProcAddress(hModule, "CiInitialize");
    if (PCiInitialize == NULL) {
        FreeLibrary(hModule);
        return NULL;
    }
    for (WORD i = 0; i < 0x200; i++) {
        ptr = (PBYTE)PCiInitialize + i;
        if (*(PULONG_PTR)(ptr) == 0x8B48C78B4CCB8B4CLL) {
            if (*(PDWORD)(ptr + 8) == 0xE8CD8BD6) {
                PCipInitialize = ptr + *(PDWORD)(ptr + 0xC) + 0x10;
                break;
            }
        }
    }
    if (PCipInitialize == NULL) {
        FreeLibrary(hModule);
        return NULL;
    }
    for (WORD i = 0; i < 0x200; i++) {
        ptr = (PBYTE)PCipInitialize + i;
        if (*(PULONG_PTR)(ptr) == 0xEC83485641544157LL) {
            if (*(PDWORD)(ptr + 8) == 0xE98B4940) {
                Pg_CiOptions = ptr + *(PBOOL)(ptr + 0xE) + 0x12;
                break;
            }
        }
    }
    if (Pg_CiOptions == NULL) {
        FreeLibrary(hModule);
        return NULL;
    }
    offset = (ULONG_PTR)Pg_CiOptions - (ULONG_PTR)hModule;
    FreeLibrary(hModule);
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
    {
        TCHAR szDriver[1024];
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (DWORD i = 0; i < cDrivers; i++)
        {
            if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
            {
                if (lstrcmpiW(szDriver,L"ci.dll") == 0) {
                    PNtg_CiOptions = (PBYTE)drivers[i] + offset;
                    break;
                }
            }
        }
    }
    cout << hex << offset << endl;
    return PNtg_CiOptions;
}

int main() {
    cout << Getg_CiOptionsAddress() << endl;
    return 0;
}
