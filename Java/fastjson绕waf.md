# Fastjson绕waf

Fastjson绕waf从三个方面入手:  

1. 键值对外部
2. 键
3. 值

## 键值对外部

键值对外部包括最外部的 __{}__ 区域

### 添加空白字符

com.alibaba.fastjson.parser.JSONLexerBase#skipWhitespace方法中会忽视以下字符：  

* 空格
* \r
* \n
* \t
* \f
* \t  

因此可以在键值对外部添加这些字符。

### 添加注释

键值对之外中如果出现/会被忽略，如果出现/**/，那么还会忽略里面所有的内容。

### 添加多个逗号

默认开启的Feature.AllowArbitraryCommas，会忽视最外层大括号中多余的逗号。

### 添加多个大括号

json数据最外部的 __{__ 和 __}__ 可以添加任意个数

### 字段名不使用双引号包裹

默认开启的Feature.AllowUnQuotedFieldNames允许字段名的键不用被引号包裹  
默认开启的Feature.AllowSingleQuote允许字段名的键被单引号包裹

## 键

### 键值编码

com.alibaba.fastjson.parser.JSONLexerBase#scanSymbol中，如果键中有字符以\u或者\x开头，会对其进行Unicode和Hex解码。  
__使用该方式时键必须被引号(单引号或者双引号)包裹__

### 添加下划线或者减号

在解析 __字段__ 键时，如果键名中存在下划线或者减号，会被忽略。  
__对原本就存在下划线的字段类无效，例如TemplatesImpl链__

1. 1.2.36版本前
只能使用其中一种符号，不能混合使用，不限数量。
2. 1.2.36版本后
能够两种符号混合使用。  

### 添加is前缀

1.2.36版本后会去除字段键的is前缀。

## 值

### 编码

值支持Unicode、Hex、Base64编码。

1. Unicode和Hex能够混合使用,能用在@type的值中,但不能用在byte[]类型的字段值上。
2. Base64只能用在字段类型是byte[]的值上，在com.alibaba.fastjson.util.IOUtils#decodeBase64方法中，会将值开头和结尾的非Base64字符去除，因此可以在值开头或者结尾添加非Base64字符。
