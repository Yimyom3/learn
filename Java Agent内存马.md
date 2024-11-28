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
        VirtualMachine vm = VirtualMachine.attach(pid); //建立与目标JVM的连接，pid为目标JVM的进程pid
        vm.loadAgent(jarPath); //将agentmain生成的jar包注入到目标JVM中，注入成功会执行agentmain方法
        vm.detach(); //断开与目标JVM的连接
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

transform()方法返回的结果将作为转换器的内容，

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

4. 代理类

    ```java
    package com.demo.Main;

    import java.io.IOException;
    import java.util.Scanner;
    import com.sun.tools.attach.AgentInitializationException;
    import com.sun.tools.attach.AgentLoadException;
    import com.sun.tools.attach.AttachNotSupportedException;
    import com.sun.tools.attach.VirtualMachine;

    public class Main {

        public static void main(String[] args) throws IOException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {
            Scanner sc = new Scanner(System.in);
            String pid = sc.nextLine();
            System.out.println("pid: " + pid);
            VirtualMachine vm = VirtualMachine.attach(pid);
            System.out.println("attach success");
            vm.loadAgent("agent.jar");
            System.out.println("load agent success");
            vm.detach();
            System.out.println("detach success");
        }
    }
    ```

5. 被代理类

    ```java
    package org.example;

    import java.util.Scanner;
    import org.example.Test02;

    public class Test01 {
        public static void main(String[] args) {
            say();
            Scanner sc = new Scanner(System.in);
            sc.nextLine();
            sc.close();
            say();
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
