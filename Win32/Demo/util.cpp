#include "util.h"

DWORD GetPid(WCHAR* szName)
{
    HANDLE hprocessSnap;
    PROCESSENTRY32  pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    hprocessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hprocessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    if (Process32First(hprocessSnap, &pe32))
    {
        do {
            if (!wcscmp(szName, pe32.szExeFile))
                return (int)pe32.th32ProcessID;
        } while (Process32Next(hprocessSnap, &pe32));

    }
    CloseHandle(hprocessSnap);
    return 0;
}

BOOL PrivilegeDebug() {
    BOOL flag = FALSE;
    HANDLE hToken;
    LUID lUid;
    TOKEN_PRIVILEGES tp, tpPrevious;
    DWORD retLength;

    //���Ի�ȡ��ǰ�̵߳�����
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)) {
        DWORD code = GetLastError();
        if (code == ERROR_NO_TOKEN) {
            // ����߳�û�����ƣ���򿪵�ǰ��������
            if (ImpersonateSelf(SecurityImpersonation)) {
                if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
                    return flag;
                }
            }
            else
            {
                return flag;
            }
        }
        else { 
            cout << "unknown error, code is " << code << endl;
            return flag;
        }
    }

    /*
    ��ȡdebug��Ȩ�ı�ʶ����debug��Ȩ��һ���������Ȩ����Ҫ����ԱȨ�޲��ܻ�ȡ���������ִ�����²�����
     1. ���ӵ��������̡�
     2. �����������̡�
     3. ��ȡ��д���������̵��ڴ档
     4. �����������̵����ȼ���
     5. ��ֹ�������̡�
    */
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &lUid)) {
        cout << "find debug privilege fail" << endl;
        return flag;
    }

    //��ʼ��������Ȩ�ṹ��
    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1; //������������Ȩ������
    tp.Privileges[0].Luid = lUid; //������ȨΪdebug
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; //������ȨΪ����״̬

    //�����߳����Ƶ���ȨΪdebug������tpPrevious����ԭ������Ȩ
    if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &retLength)) {
        DWORD code = GetLastError();
        //�߳����Ƶ�����Ȩ�ɹ�
        if (code == ERROR_SUCCESS) {
            cout << "debug privilege enable successfully!" << endl;
            flag = TRUE;
            CloseHandle(hToken);
            return flag;
        }
        else
        {
            cout << "Failed to enable debug privilege. Error code: " << code << endl;
            return flag;

        }
    }
    else
    {
        return flag;
    }

    ////�ָ��߳�����ԭ�ȵ���Ȩ
    //if (AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, retLength, NULL, NULL)) {
    //    DWORD code = GetLastError();
    //    //�߳�������Ȩ�ָ��ɹ�
    //    if (code == ERROR_SUCCESS) {
    //        cout << "Token privileges restored successfully!" << endl;
    //    }
    //    else
    //    {
    //        cout << "Token privileges restored failed! Error code: " << code << endl;

    //    }
    //}
}

BOOL ChangeFunc(LPVOID funcAddress, UCHAR buf[], SIZE_T size) {
    //��Щ����x86�ϵ��÷������ջ��WINAPI�����ĺ����Ǳ����÷������ջ��
    //unsigned char buf[] = "\xb8\x20\xff\xff\xff\xc3"; //int����ֵ�޸�Ϊ2024��ָ��
    //unsigned char buf[] = "\xb0\x40\xc3"; //bool����ֵ�޸�Ϊfalse��ָ��
    //unsigned char buf[] = "\xc3"; //ֱ�ӽ���������ָ��
    //unsigned char buf[] = "\xb8\00\00\00\00\xc3"; //����null��ָ��
    //unsigned char buf[] = "\xe9\00\00\00\00"; //��������ת��Ŀ�ĵ�ַ����4���ֽ���ƫ�Ƶ�ַ��ƫ�Ƶ�ַ = Ŀ�ĵ�ַ - (eip+5)��jmpָ��ռ5���ֽڣ�����+5
    /*
    �ܽ�: ��mov��ָ����\xb8ʱ����Ҫ�޸�����eax�Ĵ�����ֵ
          ��mov��ָ����\xb0ʱ��ֻ��Ҫ�޸�al��ֵ
          ����������ֵ����1���ֽڵ�ʱ�򣬻�ȡ����eax�Ĵ�����ֵ��Ϊ���
          ����������ֵֻ��1���ֽڵ�ʱ��ֻ��ȡal�е�ֵ��Ϊ�����eax�е������ֽڶԺ������ؽ��û��Ӱ��
    */

    DWORD old;
    HANDLE handle = GetCurrentProcess();
    if (VirtualProtectEx(handle, funcAddress, size, PAGE_EXECUTE_READWRITE, &old)) {
        WriteProcessMemory(handle, funcAddress, buf, size, NULL);
        VirtualProtectEx(handle, funcAddress, size, old, &old);
        CloseHandle(handle);
        return TRUE;
    }
    CloseHandle(handle); 
    return FALSE;
}

VOID ExecShellCode(LPVOID shellCode,SIZE_T size) {
    LPVOID lp = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lp != nullptr) {
        memcpy(lp, shellCode, size);
        ((void (*)())lp)();
    }
}