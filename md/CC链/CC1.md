# CC1链基础

## 利用条件

>jdk版本小于8u71  
>CommonsCollections <= 3.2.1  

## 环境准备

1. 下载jdk-8u65  
<https://download.oracle.com/otn/java/jdk/8u65-b17/jdk-8u65-windows-x64.exe>  
2. maven拉取CC依赖

    ```xml
        <dependencies>
                
                <dependency>
                    <groupId>commons-collections</groupId>
                    <artifactId>commons-collections</artifactId>
                    <version>3.2.1</version>
                </dependency>
            </dependencies>
    ```

3. sun包源码替换  
该链中需要用到sun包中的类，反编译不方便调试，需要去下载对应的openjdk源码。  
下载地址:<https://hg.openjdk.org/jdk8u/jdk8u/jdk/rev/af660750b2f4>  
点击左边的zip下载压缩包，解压后将/src/share/classes的sun目录剪切到jdk解压的src目录下，添加为项目的SDK。

##
