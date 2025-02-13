#include "pch.h"
#include <fstream>
#pragma warning(disable : 4996)

int run(int offset) {
    HANDLE hFile = CreateFileA("C:\\Users\\lw0122106\\Desktop\\code\\C++\\DemoDll\\x64\\Release\\DemoDll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    HANDLE heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE,0,0);
    if (heap == NULL) {
        CloseHandle(hFile);
        return -1;
    }
    LPVOID buff = HeapAlloc(heap, HEAP_ZERO_MEMORY, fileSize);
    if (buff == NULL) {
        CloseHandle(hFile);
        CloseHandle(heap);
        return -1;
    }
    DWORD bytesRead;
    if (ReadFile(hFile, buff, fileSize, &bytesRead, NULL)) {
        cout << "PEAddress: " << buff << endl;
        cout << "PE ReflectiveLoader Offset: " << hex << offset << endl;
        BYTE* ReflectiveLoader = ((BYTE*)buff + offset);
        BOOL state = ((BOOL(*)())ReflectiveLoader)();
        CloseHandle(hFile);
        CloseHandle(heap);
        return state;
    }
    CloseHandle(hFile);
    CloseHandle(heap);
    return -1;
}

DWORD GetOffset() {
    HMODULE hModule = LoadLibraryA("C:\\Users\\lw0122106\\Desktop\\code\\C++\\DemoDll\\x64\\Release\\DemoDll.dll");
    if (hModule) {
        return (ULONG64)GetProcAddress(hModule, "ReflectiveLoader") - (ULONG64)hModule;
    }
    return NULL;
}

bool SaveDllToFile() {
    // 加载DLL并获取其基地址
    HMODULE hModule = LoadLibraryA("C:\\Users\\lw0122106\\Desktop\\code\\C++\\DemoDll\\x64\\Release\\DemoDll.dll");
    if (hModule == NULL) {
        return false;
    }
    // 获取模块信息
    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(MODULEINFO))) {
        FreeLibrary(hModule);
        return false;
    }
    // 打开输出文件
    ofstream outFile("C:\\Users\\lw0122106\\Desktop\\code\\C++\\2.bin", ios::binary);
    if (!outFile.is_open()) {
        FreeLibrary(hModule);
        return false;
    }
    // 将模块内容写入文件
    outFile.write(reinterpret_cast<char*>(moduleInfo.lpBaseOfDll), moduleInfo.SizeOfImage);
    // 关闭文件和释放模块
    outFile.close();
    FreeLibrary(hModule);
    return true;
}

int main() {
    DWORD offset = GetOffset();
    if (offset != NULL) {
        offset -= 0xc00;
        cout << run(offset) << endl;
    }
    //cout << hex << offset << endl;
}