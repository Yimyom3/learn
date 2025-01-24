# PE文件结构

## 基础知识

1. PE文件是指Windows下存储在磁盘上的可执行文件的总称，常见的后缀有DLL、EXE、OCX、SYS等。
2. 当PE文件被加载到内存中后，称之为映像文件。
3. 由于内存的结构布局和磁盘的结构布局存在差异，所以PE文件并不是原封不动的被加载到内存中，而是通过操作系统装载器进行对应的转换。  
   >简而言之，PE文件的内容和映象文件的内容会有所不同
4. 相对虚拟地址(RVA)是指在映象文件中，一个地址相对于映象文件内存中基址的偏移地址,即 目标地址 = 映像文件基址 + RVA

## PE文件结构分析

一个PE文件从起始位置开始依次是DOS头、NT头、节表和节区。

### DOS头

DOS头是PE文件的起始位置，用于兼容MS-DOS操作系统，由IMAGE_DOS_HEADER和IMAGE_DOS_STUB两部分组成。  
>DOS头会被操作系统加载器原封不动的加载到内存中。

#### IMAGE_DOS_HEADER

IMAGE_DOS_HEADER固定占64字节，对应的结构体为:

``` cpp
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

其中最关键的是e_magic和e_lfanew成员，表示的含义为:  
>e_magic: 最前的4字节，DOS头的魔数，必须固定为4D5A(MZ)  
>e_lfanew: 最后的4字节，表示NT头的RVA，操作系统装载器需要根据这个值来定位PE文件的NT头的位置  

IMAGE_DOS_HEADER的其它成员都不重要，可以为任意值。

#### IMAGE_DOS_STUB

IMAGE_DOS_STUB(DOS存根)是一段简单的DOS程序，主要用来输出“This program cannot be run in DOS mode.”的提示语句。然后退出程序，表示该程序不能在DOS下运行  
IMAGE_DOS_STUB的大小不固定，并且即使映象文件没有DOS存根，程序也能正常执行，所以无关紧要。

### NT头

NT头中包含了PE文件的主要信息，是PE文件的核心，其结构体为:

```cpp
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
```

IMAGE_NT_HEADERS由一个Signature、一个IMAGE_FILE_HEADER结构体、一个IMAGE_OPTIONAL_HEADER结构体组成。  
>NT头除了IMAGE_OPTIONAL_HEADER结构体的ImageBase成员在成为映象文件后会被修正成映象文件的基址，其余都原封不动的加载到内存中。

#### Signature

Signature是NT的签名，占4字节，必须固定为50450000(PE00)

#### IMAGE_FILE_HEADER

IMAGE_FILE_HEADER是标准PE头，占20字节，其结构体为:

```cpp
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

>Machine: 表示PE文件可以在什么样的CPU上运行，0200代表因特尔安腾，014C表示32位，8664表示64位  
>NumberOfSections: 表示PE文件中节的个数，Windows下规定最多为96个  
>TimeDateStamp: 表示PE文件被创建时的时间戳  
>PointerToSymbolTable: 调试用的，不重要，一般为0  
>NumberOfSymbols: 调试用的，不重要，一般为0  
>SizeOfOptionalHeader: 表示IMAGE_OPTIONAL_HEADER的字节大小  
>Characteristics: PE文件的一些特征，用位代表

#### IMAGE_OPTIONAL_HEADER

IMAGE_OPTIONAL_HEADER是对IMAGE_FILE_HEADER的拓展，包含PE文件的额外信息。  
IMAGE_OPTIONAL_HEADER在32位和64位下有一些区别。
IMAGE_OPTIONAL_HEADER在32位下占224字节，其结构体为:

```cpp
typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

>Magic: 表示PE文件位数的魔数，0B01表示是32位可执行程序，0B02表示是64位可执行程序，0701表示是ROM文件  
>MajorLinkerVersion: 链接器的主版本号  
>MinorLinkerVersion: 链接器的次版本号  
>SizeOfCode: 代码节(.text)的总大小  
>SizeOfInitializedData: 初始化数据节(.data)的总大小  
>SizeOfUninitializedData: 未始化数据节(.bss)的总大小  
>AddressOfEntryPoint: 映象文件中入口函数的RVA  
>BaseOfCode: 映象文件中代码节的RVA  
>BaseOfData: 映象文件中数据节的RVA  
>ImageBase:映象文件中第一个字节的首选地址，也就是映象文件的基址  
>SectionAlignment: 映象文件中节区在内存中的对齐大小，默认为系统的页面大小(0x1000),也就是说在映象文件中，节区的起始地址必须是0x1000的倍数。  
>FileAlignment: 表示PE文件中节区的对齐大小，默认为0x200，也就是说节区在PE文件中的起始地址必须是0x200的倍数。  
>MajorOperatingSystemVersion: 表示运行映象文件所需操作系统的主版本号  
>MinorOperatingSystemVersion: 表示运行映象文件所需操作系统的次版本号  
>MajorImageVersion: 表示映象文件的主版本号  
>MinorImageVersion: 表示映象文件的次版本号  
>MajorSubsystemVersion: 表示子系统的主版本号  
>MinorSubsystemVersion: 表示子系统的次版本号  
>Win32VersionValue: Windows操作系统保留成员，必须为0  
>SizeOfImage: 表示映象文件在内存中的总大小  
>SizeOfHeaders: 表示PE文件所有头的总大小，会向上舍入为FileAlignment的倍数  
>CheckSum: 表示映象文件的校验和，即数字签名，PE文件被加载时需要进行校验，无签名为0  
>Subsystem: 表示运行映象文件需要的子系统，例如GUI或者CUI  
>DllCharacteristics: 表示映象的DLL特征  
>SizeOfStackReserve: 表示运行时为每个线程栈保留内存的大小，默认1MB  
>SizeOfStackCommit:  表示运行时每个线程栈初始占用内存大小  
>SizeOfHeapReserve:  表示运行时为进程堆保留内存大小  
>SizeOfHeapCommit: 表示运行时进程堆初始占用内存大小  
>LoaderFlags: 过时成员，必须为0  
>NumberOfRvaAndSizes: 表示IMAGE_DATA_DIRECTORY数组的长度  
>IMAGE_DATA_DIRECTORY DataDirectory[NumberOfRvaAndSizes]: 数据目录表数组，数组中的每个成员由VirtualAddress和Size组成，VirtualAddress表示数据目录的RVA，size表示数据目录的大小

IMAGE_OPTIONAL_HEADER在64位下占240字节，其结构体为:

```cpp
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```

>64位的IMAGE_OPTIONAL_HEADER没有BaseOfData成员，而是合并成ImageBase成员，同时SizeOfStackReserve、SizeOfStackCommit、SizeOfHeapReserve、SizeOfHeapCommit这4个成员数据类型为ULONGLONG

### 节表

节表是一个IMAGE_SECTION_HEADER结构体数组，其中每一个IMAGE_SECTION_HEADER用于描述一个对应的节的信息，windows根据节表的描述加载每个节。  
一个IMAGE_SECTION_HEADER结构体占40字节，其结构体为:

```cpp
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

错了，，，，，IMAGE_SECTION_HEADER根本不是代表对应节的信息，而是所有已加载节的信息

>Name[8]: 节的名称，8字节字符串，一般是以.开头的，可以随意更改，操作系统装载器并不依靠这个名称寻找对应的节，而是根据数据目录中的表。  
>Misc.PhysicalAddress: 文件地址偏移量，没啥用  
>Misc.VirtualSize: 表示到加载到内存后所有节的总大小，该节大小 = 下一个总大小 - 当前总大小  
>VirtualAddress: 表示节相对于映象文件基址的偏移量  
>SizeOfRawData: 表示节在磁盘上的总大小  
>PointerToRawData: 表示节在PE文件中的RVA  
>PointerToRelocations: 调式用的，不重要  
>PointerToLinenumbers: 调式用的，不重要  
>NumberOfRelocations: 调式用的，不重要  
>NumberOfLinenumbers: 调式用的，不重要  
>Characteristics: 描述节的属性标志(例如代码/数据、可读/可写等)，用位表示

当Misc.VirtualSize大于SizeOfRawData时，多余的部分会用0填充

### 节区
