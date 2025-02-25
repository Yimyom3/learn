# ELF文件结构

ELF代表Executable and Linkable Forma，是Linux下一种对可执行文件、目标文件和库使用的文件格式，主要包括3种类型文件:

* 可重定位文件(relocatable)：编译器和汇编器产生的.o文件，被Linker所处理  
* 可执行文件(executable)：Linker对.o文件进行处理输出的文件，进程映像
* 共享对象文件(shared object)：动态库文件.so和静态链接库文件.a

ELF文件主要由5部分组成:

* ELF头(ELF header): 描述体系结构和操作系统等基本信息
* 程序头表(program header table): 这个是从运行的角度来看ELF文件的，主要给出了各个segment的信息，在汇编和链接过程中没用
* 节区(sections): 各个节
* 节区头表(section header table): 这个保存了所有的section的信息，这是从编译和链接的角度来看ELF文件的
* 段区(segments): 各个段

>ELF中节是链接时的概念，而段是执行时的加载单元。

## ELF头(ELF header)

ELF header在32位下占52个字节，结构体为:

```cpp
typedef struct {
    unsigned char e_ident[16];
    unsigned short e_type;
    unsigned short e_machine;
    unsigned int e_version;
    unsigned int e_entry;
    unsigned int e_phoff;
    unsigned int e_shoff;
    unsigned int e_flags;
    unsigned short e_ehsize;
    unsigned short e_phentsize;
    unsigned short e_phnum;
    unsigned short e_shentsize;
    unsigned short e_shnum;
    unsigned short e_shstrndx;
}Elf32_Ehdr;
```

* e_ident:16字节，包含ELF魔数和其他的文件属性，比如架构、编码方式等
  * [0-3]固定为7F454C46的魔数
  * [4]表示ELF文件的位数，1代表32位，2表示64位
  * [5]表示数据编码方式，1代表小端序，2代表大端序
  * [6]表示ELF文件头的版本号
  * [7]表示操作系统/ABI类型，0代表UNIX系统，3代表Linux扩展，9代表FreeBSD，97表示ARM架构扩展
  * [8-15]为保留字段，一般为0
* e_type:表示ELF文件的类型，1代表可重定位文件，2代表可执行文件，3代表共享目标文件
* e_machine:表示ELF文件运行所需平台架构，3代表x86_32,40代表ARM_32,62代表x86_64，183代表ARM_64
* e_version:ELF文件的版本
* e_entry:程序入口的虚拟地址，对于可执行文件来说，当ELF文件加载完成后，将从这个地址开始执行。对于其它文件，该值为0
* e_phoff:程序头表的偏移量，没有则为0
* e_shoff:节区头表的偏移量，没有则为0
* e_flags:处理器特定的标志位
* e_ehsize:指明ELF头的大小
* e_phentsize:程序头表每个表项的大小
* e_phnum:程序头表表项的个数
* e_shentsize:节区头表每个表项的大小
* e_shnum:节区头表表项的数目
* e_shstrndx: 存储字符串表在节区头表中的索引

ELF header在64位下占64个字节，结构体为:

```cpp
typedef struct {
    unsigned char e_ident[16];
    unsigned short e_type;
    unsigned short e_machine;
    unsigned int e_version;
    unsigned long long e_entry;
    unsigned long long e_phoff;
    unsigned long long e_shoff;
    unsigned int e_flags;
    unsigned short e_ehsize;
    unsigned short e_phentsize;
    unsigned short e_phnum;
    unsigned short e_shentsize;
    unsigned short e_shnum;
    unsigned short e_shstrndx;
}Elf64_Ehdr;
```

## 程序头表(program header table)

程序头表是一个数组，每个元素称之为程序头表项,每个表项描述了一个段的信息，这些段用于指导加载器如何将文件加载到内存中  
程序头表项在32位下占32字节，结构体定义为:

```cpp
typedef struct
{
    unsigned int p_type;
    unsigned int p_offset;
    unsigned int p_vaddr;
    unsigned int p_paddr;
    unsigned int p_filesz;
    unsigned int p_memsz;
    unsigned int p_flags;
    unsigned int p_align;
} Elf32_phdr;
```

* p_type: 段的类型
  * 1代表PT_LOAD，表示段会进行内存映射，比如只读代码段，数据段等
  * 3代表PT_INTERP，表示特殊内存段，该段内存记录了动态加载解析器的访问路径字符串
  * 6代表PT_PHDR，表示程序头表自身的信息的段，也就是说程序头表本身也被视为一个段
* p_offset: 段在ELF文件中的偏移量
* p_vaddr: 段在内存中的偏移量
* p_paddr: 段在内存中的虚拟地址，无实际意义，一般和p_vaddr相同
* p_filesz: 段在ELF文件中的大小
* p_memsz: 段在内存中的大小
* p_flags: 段的权限标志组合
  * 1代表PF_X，表示可执行
  * 2代表PF_W，表示可写
  * 4代表PF_R，表示可读
* p_align: 段对齐大小，要求满足: (vaddr - offset) % align == 0

程序头表项在64位下占56字节，结构体定义为:

```cpp
typedef struct 
{
    unsigned int p_type;
    unsigned int p_flags;
    unsigned long long p_offset;
    unsigned long long  p_vaddr;
    unsigned long long  p_paddr;
    unsigned long long  p_filesz;
    unsigned long long  p_memsz;
    unsigned long long  p_align;
} Elf64_Phdr;
```

## 节区头表(section header table)

节区头表也是一个数组，每个元素称之为节区头表项,每个表项描述了一个节的信息
节区头表项在32位下占40字节，结构体定义为:

```cpp
typedef struct{
    unsigned int sh_name;
    unsigned int sh_type;
    unsigned int sh_flags;
    unsigned int sh_addr;
    unsigned int sh_offset;
    unsigned int sh_size;
    unsigned int sh_link;
    unsigned int sh_info;
    unsigned int sh_addralign;
    unsigned int sh_entsize;
}Elf32_Shdr;
```

* sh_name: 节的名称,是节区中.shstrtab节的偏移量
* sh_type: 节的类别
  * 0代表SHT_NULL,表示未使用的表
  * 1代表SHT_PROGBITS,表示代码表
  * 2代表SHT_SYMTAB,表示符号表
  * 3代表SHT_STRTAB,表示字符串表
  * 4代表SHT_RELA,表示带加数的重定位条目表
  * 5代表SHT_HASH，表示符号哈希表
  * 6代表SHT_DYNAMIC,表示动态连接信息表
  * 8代表SHT_NOBITS,表示bss表
  * 9代表SHT_REL，表示不带加数的重定位条目表
  * 11代表SHT_DYNSYM,表示动态符号表
* sh_flags: 节的属性
* sh_addr: 若此节在进程的内存映像中出现，则表示内存中相对于基址的偏移量。
* sh_offset: 文件中节的偏移量
* sh_size: 节在文件中的大小，如果节的类别是SHT_DYNAMIC，那么虽然不为0但不占文件中的空间
* sh_link: 如果节的类型是与链接相关的,例如符号节或者重定位节，表示节使用的字符串所位于节区头表的下标，其他无意义
* sh_info: 如果节是重定位节，表示重定位的节所位于节区头表的下标，其他无意义
* sh_addralign: 节的对齐大小
* sh_entsize: 如果该部分包含固定大小的条目，则这里是每个条目的大小

节区头表项在64位下占64字节，结构体定义为:

```cpp
typedef struct{
    unsigned int sh_name;
    unsigned int sh_type;
    unsigned long long sh_flags;
    unsigned long long sh_addr;
    unsigned long long sh_offset;
    unsigned long long sh_size;
    unsigned int sh_link;
    unsigned int sh_info;
    unsigned long long sh_addralign;
    unsigned long long sh_entsize;
}Elf64_Shdr;
```

### 动态符号表

节区头表中sh_type为SHT_DYNAMIC类型的节称之为动态符号表，导出函数的符号信息一般存储在动态符号表  
动态符号表是一个数组，数组长度为sh_size/sh_entsize  
每个成员都是一个结构体，在32位下的定义为:

```cpp
typedef struct
{
  unsigned int st_name;
  unsigned int st_value;
  unsigned int st_size;
  unsigned char st_info;
  unsigned char st_other;
  unsigned short st_shndx;
} Elf32_Sym;
```

* st_name: 符号名在符号表字符串表中的偏移量
* st_value: 符号相对于基址的偏移量
* st_size: 符号相关的内存大小
* st_info: 指明了符号的绑定属性和类型，其中高4位为绑定属性，低4位为符号类型(重点)
  * 0代表STT_NOTYPE,表示未指定类型
  * 1代表STT_OBJECT,表示数据对象(变量、数组等)
  * 2代表STT_FUNC,表示函数类型(导出函数)
  * 3代表STT_SECTION,表示与节区关联的符号(用于重定位)
  * 4代表STT_FILE,表示文件名符号(通常为源文件、目标文件名)
  * 5代表STT_COMMON,表示未初始化的公共块符号(BSS段)
  * 6代表STT_TLS,表示线程本地存储符号
  * 10代表STT_GNU_IFUNC,表示延迟绑定函数(导出函数也需要有)
* st_other: 没啥用,一般为0
* st_shndx: 符号所在的段下标

在64位下的定义为:

```cpp
typedef struct
{
  unsigned int st_name;
  unsigned char st_info;
  unsigned char st_other;
  unsigned short st_shndx;
  unsigned long long st_value;
  unsigned long long st_size;
} Elf64_Sym;
```

## ELF文件获取导出函数步骤

1. 解析ELF头，获取e_shoff(节区头表数组偏移量)、e_shentsize(节区头表数组成员大小)、e_shnum(节区头表数组成员数量)
2. 从e_shoff遍历每个节表成员，直到sh_type为SHT_DYNSYM(动态导出表)，得到符合条件的sh_offset(对应节的偏移量)、sh_size(对应节的大小)、sh_link(对应节所位于节区索引)、sh_entsize(对应节中条目的大小)
3. 从e_shoff+(sh_link*e_shentsize)开始，解析符号表字符串表，得到符号表字符串节的偏移量shdr_sh_offset
4. 使用sh_size/sh_entsize得到动态导出表的条目数量，遍历每个条目(Elf64_Sym结构体)，得到st_name偏移量，然后从shdr_sh_offset + st_name 处取字符串看是否与目标函数名相同，如果相同的话，那么st_value的值就是该函数相对于基址的偏移量

```cpp
#include <iostream>
#include <fstream>
using namespace std;

unsigned long long GetFuncOffset(const char* fileName, const char* funcName) {
 ifstream file(fileName, ios::binary);
    if (!file.is_open()) {
        return 0;
    }
    file.seekg(0, ios::end);
    int size = file.tellg();
    file.seekg(0, ios::beg);
    char* buffer = new char[size];
    file.read(buffer, size);
    file.close();
    if (*(unsigned int*)buffer != 0x464c457f) {
        cout << "targe file is not a ELF file" << endl;
        delete[] buffer;
        return 0;
    }
    unsigned long long e_shoff = *(unsigned long long*)((unsigned char*)buffer + 0x28); //节区头表偏移量
    unsigned short e_shentsize = *(unsigned short*)((unsigned char*)buffer + 0x3a); //节区头表每个表项的大小
    unsigned short e_shnum = *(unsigned short*)((unsigned char*)buffer + 0x3c); //节区头表表项的数目
    unsigned char* pshoff = (unsigned char*)buffer + e_shoff; //节区头表指针
    unsigned long long sh_offset = 0;
    unsigned long long sh_size = 0;
    unsigned int sh_link = 0;
    unsigned long long sh_entsize = 0;
    for (unsigned short i = 0; i < e_shnum; i++) { //遍历节区头表
        unsigned int sh_type = *(unsigned int*)(pshoff + 4); //对应节的类型
        if(sh_type != 11) //判断对应节的类型是否是动态符号表
        {
            pshoff += 64;
            continue;
        }
        sh_offset = *(unsigned long long*)(pshoff + 0x18); //动态符号表的偏移量
        sh_size = *(unsigned long long*)(pshoff + 0x20); //动态符号表的大小
        sh_link = *(unsigned int*)(pshoff + 0x28); //动态符号表使用的字符串所位于节区头表的下标索引
        sh_entsize = *(unsigned long long*)(pshoff + 0x38); //动态符号表中每个条目的大小
        break;
    }
    unsigned char* psymstr = (unsigned char*)buffer + sh_offset; //动态符号表的指针
    unsigned long long count = sh_size / sh_entsize; //动态符号表数组的长度
    unsigned char* pshdr = (unsigned char*)buffer + e_shoff + (sh_link * e_shentsize);//符号表字符串表项指针
    unsigned long long shdr_sh_offset = *(unsigned long long*)(pshdr + 0x18); //符号表字符串表的偏移量
    unsigned char* psymstr_shdr = (unsigned char*)buffer + shdr_sh_offset;//符号表字符串表指针
    unsigned int st_name = 0;
    unsigned char st_info = 0;
    unsigned long long st_value = 0;
    for (unsigned long long i = 0; i < count; i++) {  //遍历动态符号表的条目
        st_name = *(unsigned int*)psymstr; //符号名称在符号表字符串表中的偏移量
        st_info = *(psymstr + 4) & 0x0f; //符号的类型
        st_value = *(unsigned long long*)(psymstr + 8); //符号的偏移量
        if (st_name == 0 || st_value == 0 || (st_info != 2 && st_info != 10) || strcmp((char*)(psymstr_shdr + st_name), funcName) != 0) {
            if (i == count - 1) {
                st_value = 0;
            }
            psymstr += sh_entsize;
            continue;
        }
        break;
    }
    delete[] buffer;
    return st_value;
}
```
