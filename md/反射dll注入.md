# 反射DLL注入

## 实现思路

1. 编写一个恶意DLL，其中有一个关键函数用于将自身DLL完成加载，一般称之为ReflectiveFunction。
2. 将恶意DLL写入目标进程的内存空间中  
3. 在目标进程中执行恶意DLL中的ReflectiveFunction，完成恶意DLL的加载  

## ReflectiveFunction

ReflectiveFunction是反射DLL注入中最关键的函数，它需要实现以下的功能:

1. 查找恶意DLL存放的基址  
2. 获取所需的Win32 API地址
3. 申请恶意DLL所需要的内存空间来完成映射节，解析导入表，重定位表等等操作

> ReflectiveFunction在加载完成之前可以调用自实现的函数,但不能调用其他系统函数，因此需要借助<intrin.h>的内置函数
