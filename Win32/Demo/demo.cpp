#include "util.h"
//#include "kernel.h"

int main() {
	//unsigned char shellcode[] = "\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x48\x8b\x40\x18\x48\x8b\x40\x10\x48\x8b\x00\x48\x8b\x00\x48\x8b\x40\x30\xc3"; //x64
	//unsigned char shellcode[] = "\x33\xc0\x64\x8b\x40\x30\x8b\x40\x0c\x8b\x40\x0c\x8b\x00\x8b\x00\x8b\x40\x18\xc3"; //x86
	HMODULE ker32 = LoadLibraryA("kernel32.dll"); 
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)ker32 + (*(LONG*)((BYTE*)ker32 + 0x3C) << 6)); 
}