# Fastjson原理分析

## 基础概念

1. JSON.toJSONString()  
    >JSON.toJSONString方法可以将一个JavaBean对象转换为字符串，转换的时候会调用该对象所有getter方法。  
    >如果添加SerializerFeature.WriteClassName参数，那么生成的json字符串会带有"@type":"对象类名"的键值对。

2. @type  
    >@type是fastjson中的一个特殊注解，用于标识要将json字符串转换为@type指定的Java类型对象。  

3. JSONObject  
    >JSONObject是fastjson中用于表示json的对象，它实现了Map接口，本质上是一个map。

4. JSON.parse()  
    >JSON.parse方法用于将json字符串转换成一个JSONObject对象。  
    >如果json字符串中有@type键值对，那么不再是转换成JSONObject对象，而是指定的Java类对象，并且会调用该类的无参构造函数和对应json字符中字段的setter方法和满足条件的getter方法。

5. JSON.parseObject()
    >JSON.parseObject方法用于将json字符串转换为JSONObject对象，无论json字符串中是否含有@type键值对。  
    >JSON.parseObject方法在内部调用了JSON.parse方法，并且最后通过toJSON方法转换成JSONObject对象。  
    >在toJSON方法中，会调用到该类的所有getter方法。

6. setter方法
    >在fastjson中，一个类的getter方法如果想要被调用，需要满足以下条件:  
    1. 方法名长度不小于4
    2. 方法名第4个字母要大写
    3. 非static方法
    4. 返回类型为void或者当前类
    5. 方法的参数只有1个
    6. 方法名以set开头

7. getter方法
    >在fastjson中，一个类的getter方法如果想要被调用，需要满足以下条件:  
    1. 方法名长度不小于4
    2. 非static方法
    3. 方法没有参数
    4. 方法名以get开头
    5. 返回值的类型需要继承自Collection、Map、AtomicBoolean、AtomicInteger、AtomicLong当中的一种。

8. json字符串解析
    >当fastjson在解析json字符串中遇到{}时，会调用JSON.parseObject()将{}中的内容解析为JSONObject对象。  
    >如果JsonObject位于键中的话，那么在反序列化后还会执行键的toString方法，最终会调用到toJSONString方法。

9. checkAutoType安全机制
    >从fastjson 1.2.25开始，引入了checkAutoType机制，加入了反序列化类的黑名单(denyList)和白名单(acceptList)。  
    >checkAutoType机制通过autoTypeSupport属性来控制AutoType机制是否开启，autoTypeSuppor默认为false。  
    >在autoTypeSupport为默认的false时，程序直接检查黑名单并抛出异常。
    >当AutoType机制开启时，会先判断@type中的类是否在白名单中，若类在白名单中则直接加载，若不在白名单继续检查黑名单，若不在黑名单，正常加载。

## 参考链接

<https://www.cnblogs.com/jasper-sec/p/17880621.html>  
<https://su18.org/post/fastjson>
