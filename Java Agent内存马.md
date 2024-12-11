# Java Agent内存马

## Java Agent简介

Java Agent是一种在不影响程序正常运行的情况下，对JVM进行动态操作的技术，在JDK 1.5以后提供。  
Java Agent可以将指定外部Jar中的Agent代码插入到正在运行的Java程序中，当运行的Java程序检测到有Agent代码插入，会暂停主程序的运行，去执行Jar中特定的方法，执行完成后再恢复主程序的运行。  
Java提供了两种实现Agent的方式: premain和agentmain

## premain

premain是一种在JVM启动时通过Javaagent参数来实现的Agent，用于JVM启动前的一些初始化操作。  
实现premain需要满足3个条件:  

1. premain生成的jar包中MANIFEST.MF配置文件中需要指定Premain-Class。

    ```yaml
    Manifest-Version: 1.0
    Premain-Class: com.demo.premain.PreMain

    ```

2. Premain-Class指定的类需要实现premain()方法

   ```java
   package com.demo.premain.PreMain;

   import java.lang.instrument.Instrumentation;

   public static void premain(String agentArgs, Instrumentation inst) {
        ...
   }
   ```

3. Java程序启动时需要使用javaagent参数指定要插入的premain Jar包

    ```java
    java -javaagent:premain.jar Main
    ```

## agentmain

agentmain是一种可以在目标JVM运行时进行动态插入的Agent，需要通过VirtualMachine来将其插入到目标JVM环境中。
实现agentmain需要满足3个条件:

1. agentmain生成的jar包中MANIFEST.MF配置文件中需要指定Agent-Class。

    ```yaml
    Manifest-Version: 1.0
    Agent-Class: com.demo.agentmain.AgentMain
    Can-Retransform-Classes: true #表示允许重新定义类

    ```

2. Agent-Class指定的类需要实现agentmain()方法

   ```java
   package com.demo.agentmain.AgentMain;

   import java.lang.instrument.Instrumentation;

   public static void agentmain(String agentArgs, Instrumentation inst) {
        ...
   }
   ```

3. VirtualMachine类可以来实现获取系统信息，内存dump、线程dump、类信息统计（例如JVM加载的类）。  
通过VirtualMachine类来将agentmain的Jar包插入目标JVM，VirtualMachine类存在于JDK目录下/lib/tools.jar中。

    ```java
    import com.sun.tools.attach.AgentInitializationException;
    import com.sun.tools.attach.AgentLoadException;
    import com.sun.tools.attach.AttachNotSupportedException;
    import com.sun.tools.attach.VirtualMachine;

    public static void main(String[] args) throws AttachNotSupportedException, AgentLoadException, AgentInitializationException {
        List<VirtualMachineDescriptor> list = VirtualMachine.list(); //获取当前系统上所有JVM信息。
        for (VirtualMachineDescriptor vmd : list) {
            System.out.println("进程ID：" + vmd.id() + "，进程名称：" + desc.displayName()); //获取jvm的进程pid和启动时的主类。
            VirtualMachine vm = VirtualMachine.attach(pid); //建立与目标JVM的连接，pid为目标JVM的进程pid
            vm.loadAgent(jarPath); //将agentmain生成的jar包注入到目标JVM中，注入成功会执行agentmain方法
            vm.detach(); //断开与目标JVM的连接
        }
    }
    ```

## Instrumentation

Instrumentation类是JVMTIAgent的一部分。Java Agent通过这个类和目标JVM进行交互。  
在Agent插入成功后，该Agent的代理程序中会得到一个Instrumentation实例，作为参数传入方法中，通过该实例，可以改变已加载Class的字节码。

### getAllLoadedClasses()

Instrumentation类的getAllLoadedClasses()方法用于获取目标JVM上所有已加载的类。

```java
Class[] getAllLoadedClasses();
```

### isModifiableClasses()

Instrumentation类的isModifiableClasses()方法用于判断目标JVM上已加载的类是否能够被修改。

```java
boolean isModifiableClass(Class<?> theClass);
```

### addTransformer()

Instrumentation类的addTransformerf()方法用于增加一个Class文件的转换器，转换器可以于改变Class二进制流的数据。  

```java
void addTransformer(ClassFileTransformer transformer,boolean canRetransform);
```

### removeTransformer()

Instrumentation类的removeTransformer()方法用于删除一个Class文件的转换器。

```java
boolean removeTransformer(ClassFileTransformer transformer);
```

### retransformClasses()

Instrumentation类的retransformClasses()方法retransformClasses()方法的作用是手动请求使用转换器去转换指定的一组已加载类。  

1. 对于没有加载的类，会使用ClassLoader.defineClass()定义它;
2. 对于已经加载的类，如果canRetransform的值为true,那么会使用ClassLoader.redefineClasses()重新定义。
3. 想要重定义类，需要代理jdk版本和被代理jdk版本一致。

```java
boolean retransformClasses(Class<?>[] classes throws UnmodifiableClassException;;
```

## ClassFileTransformer

ClassFileTransformer是一个接口，它提供了一个transform方法：

```java
byte[] transform(ClassLoader loader,String className,Class<?> classBeingRedefined,ProtectionDomain protectionDomain,byte[] classfileBuffer) {} throws IllegalClassFormatException;
```

1. loader:当前正在被加载的类的类加载器。
2. className:表示当前正在被加载的类的全限定名。
3. classBeingRedefined:仅在重新定义类时有效，表示即将被重新定义的类。
4. protectionDomain:表示当前正在被加载的类的保护域。
5. classfileBuffer:包含当前正在被加载的类的原始字节码

transform()方法返回的结果将作为转换器的内容。

## 完整代码

1. agentmain实现类

    ```java
    package com.demo.agentmain;

    import com.demo.Main.TransformerDemo;
    import java.lang.instrument.Instrumentation;
    import java.lang.instrument.UnmodifiableClassException;

    public class AgentMain {

        public static void agentmain(String args, Instrumentation inst) throws UnmodifiableClassException {
            inst.addTransformer(new TransformerDemo(),true);
            Class[] classes = inst.getAllLoadedClasses();
            for (Class cls : classes) {
                if (cls.getName().equals(TransformerDemo.className)) {
                    inst.retransformClasses(cls);
                }
            }
        }
    }
    ```

2. transform实现类

    ```java
    package com.demo.Main;

    import javassist.ClassPool;
    import javassist.CtClass;
    import javassist.CtMethod;
    import java.lang.instrument.ClassFileTransformer;
    import java.security.ProtectionDomain;

    public class TransformerDemo implements ClassFileTransformer {
        public static final String className = "org.example.Test02";
        private static final String methodName = "say";


        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
            if(className.replace("/", ".").equals(TransformerDemo.className)){
                try{
                    ClassPool classPool = ClassPool.getDefault();
                    CtClass ctClass = classPool.get(TransformerDemo.className);
                    CtMethod ctMethod = ctClass.getDeclaredMethod(TransformerDemo.methodName);
                    String source = "System.out.println(\"method changed success!\");";
                    ctMethod.setBody(source);
                    byte[] byteCode = ctClass.toBytecode();
                    ctClass.detach();
                    return byteCode;
                } catch (Exception e) {
                    return classfileBuffer;
                }
            }
            else {
                return classfileBuffer;
            }
        }
    }
    ```

3. MANIFEST.MF

    ```yaml
    Manifest-Version: 1.0
    Agent-Class: com.demo.agentmain.AgentMain
    Can-Retransform-Classes: true

    ```

4. 代理实现(注入当前进程)

    ```java
    package org.example;

    import java.lang.management.ManagementFactory;
    import java.lang.management.RuntimeMXBean;
    import com.sun.tools.attach.VirtualMachine;

    public class Test01 {

        public static void main(String[] args){
            Test02.say();
            loadAgent("agent.jar");
            Test02.say();
        }

        public static void loadAgent(String agentPath){
            try {
                String pid = getCurrentPid();
                System.out.println("pid ==> " + pid);
                VirtualMachine vm = VirtualMachine.attach(pid);
                System.out.println("attach success");
                vm.loadAgent(agentPath,null);
                System.out.println("load agent success");
                vm.detach();
                System.out.println("detach success");
            }catch (Exception e) {
            }
        }

        public static String getCurrentPid() {
            RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
            return runtimeMXBean.getName().split("@")[0];
        }
    }
    ```

    ```java
    package org.example;

    public class Test02 {
        public static void say()   {
            System.out.println("Hello World");
        }
    }
    ```

## Agent内存马的实现

agent内存马是通过agent技术去修改中间件中关键类的字节码，通过在方法中插入额外的webshell逻辑。  
agent内存马分为有文件落地和无文件落地两种方式，无文件落地方式是对有文件落地的升级。

### 有文件落地的内存马

有文件落地的内存马的植入步骤分为:

1. 编写agent.jar文件来修改目标类，添加webshell逻辑。
2. 将agent.jar放置到目标系统的磁盘上。
3. 通过selfattach向目标自身jvm进程注入agent.jar，植入webshell。

### 文件落地的缺点

1. 必须有一个agent.jar文件在目标机器的磁盘上来供目标JVM加载。
2. 因为agent注入需要依赖tools.jar，虽然tools.jar是JDK内置的，但JVM默认是不加载的，因此需要动态加载；  
   如果agent.jar中使用javassist动态修改字节码，则还需要确保目标环境存在该依赖，不存在的话也需要动态加载。  
3. 虽然有方法可以在内存中直接加载jar，但是由于jar的体积都不小，即使压缩后的字节码也非常大，如果写在代码中，那么会导致代码体积过大，当通过反序列化植入agent内存马时，会导致序列化后的字节码太大。
   >内存加载jar的方法:

   ```java
    import java.io.*;
    import java.lang.reflect.Field;
    import java.lang.reflect.Method;
    import java.net.*;
    import java.util.ArrayList;
    import java.util.List;
    import java.util.Map;
    import java.util.concurrent.ConcurrentHashMap;

    /**
    * 自定义URLStreamHandlerFactory，注册自定义协议，实现jar包在内存中动态注入
    */
    public class ResourceLoader {

        private static final Map<String, byte[]> map = new ConcurrentHashMap<>();
        private static final String customProtocol = "customProtocol";
        private static boolean flag = false;

        public static void init(String jarName, byte[] jarBytes) throws Exception {
            if (!flag) {
                registerFactory();
            }
            map.put(jarName, jarBytes);
            Method method = URLClassLoader.class.getDeclaredMethod("addURL", URL.class);  // 将JAR文件动态添加到系统类加载器的类路径
            method.setAccessible(true);
            method.invoke(ClassLoader.getSystemClassLoader(), new URL(customProtocol + ":" + jarName));
        }

        private static void registerFactory() {
            Object tomcatURLStreamHandlerFactory;
            try {
                //tomcat已经存在了URLStreamHandlerFactory对象，向这个对象添加自定义的URLStreamHandlerFactory即可。
                Class clazz = Class.forName("org.apache.catalina.webresources.TomcatURLStreamHandlerFactory");
                Method method = clazz.getMethod("getInstance");
                tomcatURLStreamHandlerFactory = method.invoke(null);
            } catch (Exception e) {
                tomcatURLStreamHandlerFactory = null;
            }
            try {
                if (tomcatURLStreamHandlerFactory != null) {
                    Method addUserFactory = tomcatURLStreamHandlerFactory.getClass().getMethod("addUserFactory", URLStreamHandlerFactory.class);
                    addUserFactory.invoke(tomcatURLStreamHandlerFactory, customProtocolFactory());
                    flag = true;
                } else {
                    URL.setURLStreamHandlerFactory(customProtocolFactory());
                    flag = true;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private static URLStreamHandlerFactory customProtocolFactory() {
            return protocol -> {
                if (customProtocol.equalsIgnoreCase(protocol)) {
                    return new URLStreamHandler() {
                        @Override
                        protected URLConnection openConnection(URL url) {
                            String key = url.toString().split(":")[1];
                            return new URLConnection(url) {
                                public void connect() {
                                }

                                public InputStream getInputStream() {
                                    return new ByteArrayInputStream(map.get(key));
                                }
                            };
                        }
                    };
                }
                return null;
            };
        }

    }
   ```

## 参考链接

<https://www.cnblogs.com/silyvin/articles/12178528.html>  
<https://xz.aliyun.com/t/10075>  
<https://xz.aliyun.com/t/11640>  
<https://github.com/BeichenDream/Kcon2021Code>  
<https://weixin.sogou.com/link?url=dn9a_-gY295K0Rci_xozVXfdMkSQTLW6cwJThYulHEtVjXrGTiVgS5FLi4EgWb-aa0XM2wzYrWzSJwwyhsRcI1qXa8Fplpd9bPXFm10HYAweWxrFyBnRRQzL7mc0tsc5kRWLLvkiC8LNR4rtJg0tWTVB3UIhcU5tUxE4IqeJX4isHqTMF2mdxNjemlnBPQY8krjTDkObOAX_MXE2NOT_gUhR_Xh3p2NkoqfUnK3u1GT8Qqkit9FA340oNcsYZVoRXpWHLaTjzSsYJSSFPgfogQ..&type=2&query=%E5%88%86%E6%9E%90%E5%93%A5%E6%96%AF%E6%8B%89%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BDJar%E6%8A%80%E6%9C%AF&token=D8152AFD49CB511B3F3968DBF1E0F9A74024424D67597D4D&k=34&h=L>
