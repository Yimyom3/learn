# C/C++编译过程

## 编译的四个阶段

C/C++语言的编译过程包括四个步骤：预处理、编译、汇编和链接:

1. 预处理: 预处理用于对C/C++代码进行基本处理，由预处理器完成，生成处理后的C/C++代码文件，预处理主要完成以下工作:

    * 删除所有的注释
    * 将所有宏替换成对应的值
    * 将#include指令包含的文件内容添加到当前文件中

2. 编译：编译阶段主要将C/C++代码转换为汇编代码，检查C/C++代码语法，生成汇编代码文件
3. 汇编：汇编过程主要将汇编代码转变为机器指令，生成对象文件
4. 链接：链接用于将各个对象文件、库文件链接到一起，检查对象文件中是否存在入口函数，生成可执行文件

## GCC

GCC是由GNU开发的编程语言编译器，主要用于Linux系统环境，它提供gcc用于编译C代码，g++用于编译C++代码

1. 预处理：使用-E参数将C/C++源文件进行预处理，得到.i的预处理文件

    ```bash
    gcc -E hello.c -o hello.i
    ```

2. 编译: 使用-S参数将预处理文件编译成汇编文件,得到.s的汇编文件

    ```bash
    gcc -S hello.i -o hello.s
    ```

3. 汇编: 使用-c参数将汇编文件编译成对象文件,得到.o的二进制对象文件

    ```bash
    gcc -c hello.s -o hello.o
    ```

4. 链接: 将多个对象文件链接到一起，得到可执行文件

    ```bash
    gcc hello.o -o hello
    ```

> 以上的任意一个步骤都可以直接到后续的另一个步骤，中间的步骤会自动完成

## MSVC

Microsoft Visual C++（简称MSVC）是微软公司的C++开发工具，它包含了Microsoft的C++编译器工具集，用于构建Windows平台上的应用程序。
> Windows原生环境不提供类似gcc、clang的C/C++语言源程序编译运行工具链,如果需要使用gcc的话，一般都使用MinGW（Minimalist GNU for Windows）配置模拟Linux下的开发环境来进行Windows下的开发。

MSVC编译器工具链主要由cl.exe与link.exe构成。其中：

* cl.exe用于控制在 Microsoft C/C++的编译器和链接器
* link.exe将通用对象文件格式 (COFF) 对象文件和库链接起来，以创建可执行文件或动态链接库

1. 预处理: 使用/P参数将C/C++源文件进行预处理，得到.i的预处理文件

    ```shell
    cl.exe hello.c  /P /C /Fi hello.i # /C: 不抽出注释 /Fi:指定生成预处理文件位置
    ```

2. 编译: 使用/Fa参数得到C/C++编译后的.asm汇编文件

    ```shell
    cl.exe hello.c /c /Fa hello.asm # /c:只编译不链接 /Fa: 指定生成汇编文件位置
    ```

3. 汇编: 使用cl.exe或者ml.exe将汇编文件编译成对象文件,得到.obj的二进制对象文件

    ```shell
    ml.exe /c /coff hello.asm /Fo hello.obj # /coff：生成COFF格式的对象文件(Windows标准格式) /Fo: 指定生成目标文件位置
    cl.exe /c hello.asm /Fo hello.obj 
    ```

4. 链接: 使用link.exe将多个对象文件链接到一起，得到可执行文件

    ```shell
    link.exe hello.obj /out:hello.exe # /out:指定可执行文件路径
    ```

> cl.exe默认会直接将C/C++源文件直接编译成.obj对象文件，然后调用link.exe自动完成链接

## Clang

Clang是LLVM项目的一个子项目，基于LLVM架构的C、C++、Objective-C编译器前端，主要用于macOS系统环境，它提供clang用于编译C代码，提供clang++用于编译C++代码。
> LLVM类似Java的虚拟机，不同的前端编译器将代码编译成统一的中间代码(LLVM IR)，再由LLVM来进行处理

## 静态链接库

静态链接库用于在链接阶段，会将汇编生成的目标文件与引用到的库一起链接打包到可执行文件中
静态链接库可以看做是是一组目标文件的集合

### Linux静态链接库

#### 命名规范

在Linux中，静态链接库的命名规范为:

```text
lib[name].a
```

lib: 固定前缀，[name]: 自定义静态库名，.a: 固定后缀

#### 创建静态链接库

首先使用gcc/g++编译C/C++代码得到.o目标文件

```bash
gcc -c hello.s -o hello.o
```

然后使用ar(归档工具)创建静态库

```bash
ar rcs libmylib.a hello.o file.o # r:替换已存在的文件 c: 创建归档文件 s: 创建索引（符号表）
```

#### 使用静态链接库

在链接阶段，可以将静态链接库和目标文件链接到一起，生成可执行文件

```bash
gcc hello.o -L/usr/local/lib -lmylib # -L:静态库所在目录(中间没有空格) -l: 自定义链接库名称(不带前后缀并且没有空格)
```

### Windows静态链接库

在Windows中，静态链接库的后缀为.lib，文件名没有必要要求

#### 创建静态链接库

首先使用cl.exe编译C/C++代码得到.obj目标文件

```bash
cl.exe /c hello.cpp /Fo hello.obj 
```

然后使用lib.exe创建静态库

```bash
lib.exe /OUT:mylib.lib hello.obj file.obj # /OUT: 指定静态链接库输出
```

#### 使用静态链接库

在链接阶段，可以将静态链接库和目标文件链接到一起，生成可执行文件

```bash
cl.exe hello.cpp /link /LIBPATH:lib mylib.lib # /link:指示编译器进入链接阶段 /LIBPATH:指定库文件的搜索路径
```
