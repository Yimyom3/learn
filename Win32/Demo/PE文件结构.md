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

Signature是NT的签名，占4字节，必须固定为0x50450000(PE00)

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
>AddressOfEntryPoint: 映象文件中入口函数的RVA(一般是CRT的地址，而非main)  
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
>IMAGE_DATA_DIRECTORY DataDirectory[NumberOfRvaAndSizes]: 数据目录表数组，后续有详解。

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
    union { //联合体的成员是互斥的，共享最大成员的内存空间
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

>Name[8]: 节的名称，8字节字符串，一般是以.开头的，可以随意更改，操作系统装载器并不依靠这个名称寻找对应的节，而是根据数据目录中的表。  
>Misc.PhysicalAddress: 文件地址，仅对BSS节生效  
>Misc.VirtualSize: 表示该节被加载到内存中的总大小(内存对齐之前)  
>VirtualAddress: 表示节相对于映象文件基址的偏移量  
>SizeOfRawData: 表示节在磁盘上的总大小(磁盘对齐之后)，如果节仅包含未初始化的数据，则为0。  
>PointerToRawData: 表示节在PE文件中的RVA  
>PointerToRelocations: 调式用的，不重要  
>PointerToLinenumbers: 调式用的，不重要  
>NumberOfRelocations: 调式用的，不重要  
>NumberOfLinenumbers: 调式用的，不重要  
>Characteristics: 描述节的属性标志(例如代码/数据、可读/可写等)，用位表示

当Misc.VirtualSize大于SizeOfRawData时，多余的部分会用0填充

### 节区

PE头后就是具体节的内容

### 数据目录

IMAGE_DATA_DIRECTORY数据目录数组中的每个成员都是一个_IMAGE_DATA_DIRECTORY结构体，占8个字节:

```cpp
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

>VirtualAddress: 表示对应数据目录表的RVA  
>Size: 表示对应数据目录表的大小  

IMAGE_DATA_DIRECTORY数据目录数组中每个位置的成员代表不同含义的数据目录表:  

```cpp
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // 导出目录表
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // 导入目录表
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // 资源目录表
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // 异常目录表
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // 安全目录表
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // 基本重定位表
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // 调式目录表
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // 特定于体系结构的数据表
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // 全局指针的相对虚拟地址表
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // 线程本地存储目录表
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // 加载配置目录表
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // 绑定导入目录表
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // 导入地址表
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // 延迟导入表
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM 描述符表
//最后一个成员是保留，固定为0
```

#### PE导入表(IMAGE_DIRECTORY_ENTRY_IMPORT)

导入表总共有4个: 导入目录表、绑定导入目录表、导入地址表、延迟导入表，其中绑定导入目录表和延迟导入表不关键。  
PE导入表用于表示映象文件需要用到哪些DLL的函数，为一个IMAGE_IMPORT_DESCRIPTOR数组，一个IMAGE_IMPORT_DESCRIPTOR描述一个导入的DLL,占20字节:

```cpp
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp; 
    DWORD   ForwarderChain;
    DWORD   Name; 
    DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
```

>DUMMYUNIONNAME.Characteristics: 如果该成员为0，则表示是数组最后一项。  
>DUMMYUNIONNAME.DUMMYUNIONNAME: 如果该成员不为0，则表示指向IMAGE_THUNK_DATA的数组(INT表)的RVA，该数组最后以0成员结束  
>TimeDateStamp: 映象绑定前，这个值是0，绑定后是导入模块的时间戳。  
>ForwarderChain: 转发链，如果没有转发器，这个值是-1。  
>Name：指向要导入模块名称的RVA。  
>FirstThunk: 如果该成员不为0，则表示指向IMAGE_THUNK_DATA的数组(IAT表)的RVA，该数组最后以0成员结束。  

PE导入表数组由一个全为0的IMAGE_IMPORT_DESCRIPTOR成员代表数组的结束，所以PE导入表导入的DLL数量为:

```cpp
size_t count = (IMAGE_DATA_DIRECTORY.Size / sizeof(IMAGE_DATA_DIRECTORY)) - 1;
```

IMAGE_THUNK_DATA结构体是一个4个成员的联合体，在32位下占4字节，定义为:

```cpp
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;     
        DWORD Function;            
        DWORD Ordinal;
        DWORD AddressOfData;
    } u1;
} IMAGE_THUNK_DATA32;
```

IMAGE_THUNK_DATA结构体在64位下占8字节，定义为:

```cpp
typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString; 
        ULONGLONG Function;         
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;   
    } u1;
} IMAGE_THUNK_DATA64;
```

其中当IMAGE_THUNK_DATA结构体值的最高位为1时，那么就抹去该最高位后，所表示的数就是要导入的函数的序号;  
当IMAGE_THUNK_DATA结构体值的最高位为0时，那么则表示的是一个RVA，指向IMAGE_IMPORT_BY_NAME结构体。  IMAGE_IMPORT_BY_NAME结构体的定义为:

```cpp
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;          //一个序号，无关紧要
    CHAR   Name[1];        //函数名称，以0结尾
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

实际上，PE文件在加载过程中，只会检索IAT表里存储的数据，而不会管INT表是否有数据。  
IAT表一般位于.rdata节中，并且在PE文件中，IAT表的内容是和INT一致的，只有被完全加载到内存中才会被修正为对应函数名的函数地址  

#### 基本重定位表(IMAGE_DIRECTORY_ENTRY_BASERELOC)

当程序被编译时，编译器假定一个特定的基址作为可执行文件的基址(IMAGE_OPTIONAL_HEADER.ImageBase),然后基于这个基址计算并嵌入了各种地址。但由于地址冲突等原因，实际上在内存中会基址会不同，这使得所有这些嵌入的地址无效。  
基本重定位表就是用来解决这个问题的，它记录了在程序加载时需要修正的地址值的相关信息，包括修正地址的位置、需要修正的字节数、需要修正的地址的类型等，一般位于.reloc节。  
基本重定位表由IMAGE_DATA_DIRECTORY结构体数组表示，数组以全0成员结束  
IMAGE_DATA_DIRECTORY结构体的定义为:

```cpp
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
//  WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION;
```

>VirtualAddress: 需重定位数据的起始RVA  
>SizeOfBlock: IMAGE_DATA_DIRECTORY结构体和TypeOffset的总大小  
>TypeOffset: 一个WORD数组，本质上不属于IMAGE_DATA_DIRECTORY结构体，它被拆分为高4位和低12位，高4位代表重定位类型，低12位是重定位地址(相对于VirtualAddress)

TypeOffset的高4位常用选项:
>IMAGE_REL_BASED_ABSOLUTE(0): 不需要重定位  
>IMAGE_REL_BASED_HIGH(1): 调整32位地址的高16位  
>IMAGE_REL_BASED_LOW(2): 调整32位地址的低16位  
>IMAGE_REL_BASED_HIGHLOW(3): 调整整个32位地址  
>IMAGE_REL_BASED_DIR64(10): 调整64位绝对地址  

重定位的步骤:

1. 获取PE文件IMAGE_OPTIONAL_HEADER.ImageBase值  

   ```plaintext
   PEaddress = IMAGE_OPTIONAL_HEADER.ImageBase
   ```

2. 获取映射文件IMAGE_OPTIONAL_HEADER.ImageBase值(基址)，计算基址和PE文件中IMAGE_OPTIONAL_HEADER.ImageBase值的差值  

   ```plaintext
   Difference = BaseAddress - PEaddress
   ```

3. 解析IMAGE_BASE_RELOCATION结构体，得到TypeOffset数组大小和要重定位的地址(基址+IMAGE_BASE_RELOCATION.VirtualAddress)

   ```plaintext
   ActualAddress  = BaseAddress + VirtualAddress
   ```

4. 解析TypeOffset成员，根据高4位选择将实际重定位地址(要重定位的地址 + TypeOffset低12位)上的值更新为差值和原值的和

   ```cpp
   SpecificAddress  = ActualAddress + Offset
   NewValue = OldValue + Difference
   ```
