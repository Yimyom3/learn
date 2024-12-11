#include <Windows.h>
//#include <tlhelp32.h>
//#include <tchar.h>
#include <iostream>
using namespace std;

//bool Inject(DWORD dwId, WCHAR* szPath)//参数1：目标进程PID  参数2：DLL路径
//{
//    //一、在目标进程中申请一个空间
//    /*
//    【1.1 获取目标进程句柄】
//    参数1：想要拥有的进程权限（本例为所有能获得的权限）
//    参数2：表示所得到的进程句柄是否可以被继承
//    参数3：被打开进程的PID
//    返回值:指定进程的句柄
//    */
//    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwId);
//    /*
//    【1.2 在目标进程的内存里开辟空间】
//    参数1：目标进程句柄
//    参数2：保留页面的内存地址，一般用NULL自动分配
//    参数3：欲分配的内存大小，字节单位
//    参数4：MEM_COMMIT：为特定的页面区域分配内存中或磁盘的页面文件中的物理存储
//    参数5：PAGE_READWRITE 区域可被应用程序读写
//    返回值：执行成功就返回分配内存的首地址，不成功就是NULL
//    */
//    size_t szie = (wcslen(szPath) + 1) * sizeof(WCHAR);
//    LPVOID pRemoteAddress = VirtualAllocEx(
//        hProcess,
//        NULL,
//        szie,
//        MEM_COMMIT,
//        PAGE_READWRITE
//    );
//
//    //二、 把dll的路径写入到目标进程的内存空间中
//
//    DWORD dwWriteSize = 0;
//    /*
//    【写一段数据到刚才给指定进程所开辟的内存空间里】
//    参数1：OpenProcess返回的进程句柄
//    参数2：准备写入的内存首地址
//    参数3：指向要写的数据的指针（准备写入的东西）
//    参数4：要写入的字节数（东西的长度+0/）
//    参数5： 返回值。返回实际写入的字节
//    */
//    BOOL bRet = WriteProcessMemory(hProcess, pRemoteAddress, szPath, szie, NULL);
//    //三、 创建一个远程线程，让目标进程调用LoadLibrary
//
//    // #5.获取模块地址
//    HMODULE hModule = GetModuleHandle(L"kernel32.dll");
//    if (!hModule)
//    {
//        printf("GetModuleHandle Error !\n");
//        CloseHandle(hProcess);
//        return FALSE;
//    }
//    // #6.获取LoadLibraryA 函数地址
//    LPTHREAD_START_ROUTINE dwLoadAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryW");
//    if (!dwLoadAddr)
//    {
//        printf("GetProcAddress Error !\n");
//        CloseHandle(hProcess);
//        CloseHandle(hModule);
//        return FALSE;
//    }
//    // //7.创建远程线程,加载dll
//        /*
//    参数1：该远程线程所属进程的进程句柄
//    参数2：一个指向 SECURITY_ATTRIBUTES 结构的指针, 该结构指定了线程的安全属性
//    参数3：线程栈初始大小,以字节为单位,如果该值设为0,那么使用系统默认大小
//    参数4：在远程进程的地址空间中,该线程的线程函数的起始地址（也就是这个线程具体要干的活儿）
//    参数5：传给线程函数的参数（刚才在内存里开辟的空间里面写入的东西）
//    参数6：控制线程创建的标志。0（NULL）表示该线程在创建后立即运行
//    参数7：指向接收线程标识符的变量的指针。如果此参数为NULL，则不返回线程标识符
//    返回值：如果函数成功，则返回值是新线程的句柄。如果函数失败，则返回值为NULL
//    */
//    HANDLE hThread = CreateRemoteThread(
//        hProcess,
//        NULL,
//        0,
//        (LPTHREAD_START_ROUTINE)dwLoadAddr,
//        pRemoteAddress,
//        NULL,
//        NULL
//    );
//    cout << "Remote Thread Stop" << endl;
//    //WaitForSingleObject(hThread, -1); //当句柄所指的线程有信号的时候，才会返回
//
//    ///*
//    //四、 【释放申请的虚拟内存空间】
//    //参数1：目标进程的句柄。该句柄必须拥有 PROCESS_VM_OPERATION 权限
//    //参数2：指向要释放的虚拟内存空间首地址的指针
//    //参数3：虚拟内存空间的字节数
//    //参数4：MEM_DECOMMIT仅标示内存空间不可用，内存页还将存在。
//    //       MEM_RELEASE这种方式很彻底，完全回收。
//    //*/
//    //VirtualFreeEx(hProcess, pRemoteAddress, 1, MEM_DECOMMIT);
//    return 0;
//}
//DWORD GetPid(WCHAR* szName)
//{
//    HANDLE hprocessSnap;
//    PROCESSENTRY32  pe32;
//    pe32.dwSize = sizeof(PROCESSENTRY32);
//    hprocessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//    if (hprocessSnap == INVALID_HANDLE_VALUE) {
//        return 0;
//    }
//    if (Process32First(hprocessSnap, &pe32))
//    {
//        do {
//            if (!wcscmp(szName, pe32.szExeFile))
//                return (int)pe32.th32ProcessID;
//        } while (Process32Next(hprocessSnap, &pe32));
//
//    }
//    else
//        CloseHandle(hprocessSnap);
//    return 0;
//}

//void run() {
//    char command[] = { 'c', 'a', 'l', 'c', '\0' };
//    system(command);
//}
//typedef int (*func)(int, int);

//void change(LPVOID func) {
//    unsigned char buf[] = "\xb8\x20\xff\xff\xff\xc3"; //int返回值修改为2024的指令
//    //unsigned char buf[] = "\xb0\x40\xc3"; //bool返回值修改为false的指令
//    //unsigned char buf[] = "\xc3"; //直接结束函数的指令
//    //unsigned char buf[] = "\xb8\00\00\00\00\xc3"; //返回null的指令
//    //总结: 当mov的指令是\xb8时，需要修改整个eax寄存器的值
//    //      当mov的指令是\xb0时，只需要修改al的值
//    // 当函数返回值超过1个字节的时候，会取整个eax寄存器的值作为结果
//    // 当函数返回值只有1个字节的时候，只会取al中的值作为结果，eax中的其他字节对函数返回结果没有影响
//
//    size_t size = sizeof(buf);
//    DWORD old;
//    HANDLE handle = GetCurrentProcess();
//    if (VirtualProtectEx(handle, func, size, PAGE_EXECUTE_READWRITE, &old)) {
//        WriteProcessMemory(handle, func, buf, size, NULL);
//        VirtualProtectEx(handle, func, size, old, &old);
//    }
//    CloseHandle(handle);
//}


int main()
{
    HANDLE hToken;
    LUID lUid;
    TOKEN_PRIVILEGES tp, tpPrevious;
    DWORD retLength;

    //尝试获取当前线程的令牌
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE,&hToken)) {
        DWORD code = GetLastError();
        if (code == ERROR_NO_TOKEN) {
            // 如果线程没有令牌，则打开当前进程令牌
            if (ImpersonateSelf(SecurityImpersonation)) {
                if (OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
                    cout << "Impersonate Self Token Success, Token Handle is " << hToken << endl;
                }
            }
        }
        else { cout << "unknown error, code is " << code << endl;}
    }

    /*
    获取debug特权的标识符，debug特权是一个特殊的特权，需要管理员权限才能获取，允许进程执行以下操作：
     1. 附加到其他进程。
     2. 调试其他进程。
     3. 读取或写入其他进程的内存。
     4. 更改其他进程的优先级。
     5. 终止其他进程。
    */
    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &lUid)) {
        cout << "find debug privilege success" << endl;
    }

    //初始化令牌特权结构体
    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1; //设置令牌中特权的数量
    tp.Privileges[0].Luid = lUid; //设置特权为debug
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; //设置特权为启用状态

    //调整线程令牌的特权为debug，并用tpPrevious保存原来的特权
    if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &retLength)) {
        DWORD code = GetLastError();
        //线程令牌调整特权成功
        if (code == ERROR_SUCCESS) {
            cout << "debug privilege enable successfully!" << endl;
        }
        else
        {
            cout << "Failed to enable debug privilege. Error code: " << code << endl;

        }
    }

    //恢复线程令牌原先的特权
    if (AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, retLength, NULL, NULL)) {
        DWORD code = GetLastError();
        //线程令牌特权恢复成功
        if (code == ERROR_SUCCESS) {
            cout << "Token privileges restored successfully!" << endl;
        }
        else
        {
            cout << "Token privileges restored failed! Error code: " << code << endl;

        }
    }
    
    //释放令牌句柄
    CloseHandle(hToken);
}
