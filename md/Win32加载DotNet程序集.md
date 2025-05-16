# 枚举CLR运行时版本

[CLRCreateInstance 函数](https://learn.microsoft.com/zh-cn/dotnet/framework/unmanaged-api/hosting/clrcreateinstance-function)  
[ICLRMetaHost 接口](https://learn.microsoft.com/zh-cn/dotnet/framework/unmanaged-api/hosting/iclrmetahost-interface)  
[ICLRRuntimeInfo 接口](https://learn.microsoft.com/zh-cn/dotnet/framework/unmanaged-api/hosting/iclrruntimeinfo-interface)  
[ICLRRuntimeHost 接口](https://learn.microsoft.com/zh-cn/dotnet/framework/unmanaged-api/hosting/iclrruntimehost-interface)  
[ICorRuntimeHost 接口](https://learn.microsoft.com/zh-cn/dotnet/framework/unmanaged-api/hosting/icorruntimehost-interface)

```cpp
ICLRMetaHost* pMetaHost = NULL;
HRESULT hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
if (FAILED(hr)) {
    std::cerr << "Failed to create ICLRMetaHost: 0x" << std::hex << hr << std::endl;
    return -1;
}

// 2. 枚举已安装的运行时
IEnumUnknown* pEnumerator = nullptr;
hr = pMetaHost->EnumerateInstalledRuntimes(&pEnumerator);
if (SUCCEEDED(hr)) {
    ICLRRuntimeInfo* pRuntimeInfo = nullptr;
    ULONG fetched = 0;

    // 遍历所有运行时
    while (pEnumerator->Next(1, reinterpret_cast<IUnknown**>(&pRuntimeInfo), &fetched) == S_OK && fetched == 1) {
        //  3. 获取运行时版本字符串
        WCHAR version[50];
        DWORD versionLength = sizeof(version) / sizeof(WCHAR);
        hr = pRuntimeInfo->GetVersionString(version, &versionLength);
        if (SUCCEEDED(hr)) {
            std::wcout << L"Installed CLR Version: " << version << std::endl;
        }
        pRuntimeInfo->Release();
    }
    pEnumerator->Release();
}
// 4 .释放资源
pMetaHost->Release();
```

* ICLRMetaHost：查询已安装的 CLR 版本、启动运行时等
* IID_PPV_ARGS：一个辅助宏，自动推导和填充对应函数所需的IID参数
*

# 调用具体版本的CLR运行时
