# JNDI注入

## JNDI简介

### rmi注入

JNDI注入rmi调用栈:

```wiki
javax.naming.InitialContext#lookup(java.lang.String)
com.sun.jndi.toolkit.url.GenericURLContext#lookup(java.lang.String)
com.sun.jndi.rmi.registry.RegistryContext#lookup(javax.naming.Name)
com.sun.jndi.rmi.registry.RegistryContext#decodeObject
javax.naming.spi.NamingManager#getObjectInstance
javax.naming.spi.NamingManager#getObjectFactoryFromReference
com.sun.naming.internal.VersionHelper12#loadClass(java.lang.String, java.lang.String)
com.sun.naming.internal.VersionHelper12#loadClass(java.lang.String, java.lang.ClassLoader)
java.lang.Class#newInstance
```

> rmi注入需要满足com.sun.jndi.rmi.object.trustURLCodebase和com.sun.jndi.ldap.object.trustURLCodebase两个系统属性都为ture

### ldap注入

JNDI注入ldap调用栈:

```wiki
javax.naming.InitialContext#lookup(java.lang.String)
com.sun.jndi.url.ldap.ldapURLContext#lookup(java.lang.String)
com.sun.jndi.toolkit.url.GenericURLContext#lookup(java.lang.String)
com.sun.jndi.toolkit.ctx.PartialCompositeContext#lookup(javax.naming.Name)
com.sun.jndi.toolkit.ctx.ComponentContext#p_lookup
com.sun.jndi.ldap.LdapCtx#c_lookup
javax.naming.spi.DirectoryManager#getObjectInstance
javax.naming.spi.NamingManager#getObjectFactoryFromReference
com.sun.naming.internal.VersionHelper12#loadClass(java.lang.String, java.lang.String)
com.sun.naming.internal.VersionHelper12#loadClass(java.lang.String, java.lang.ClassLoader)
java.lang.Class#newInstance
```

>ldap注入需要满足com.sun.jndi.ldap.object.trustURLCodebase这个系统属性为ture

## 高版本限制

高版本JDK对com.sun.jndi.rmi.object.trustURLCodebase和com.sun.jndi.ldap.object.trustURLCodebase这两个系统属性都进行了限制，从默认的true变成了false，具体开始版本为:

* rmi: jdk6u132, jdk7u122, jdk8u113
* ldap: jdk6u211, jdk7u201, jdk8u191, jdk11.0.1
