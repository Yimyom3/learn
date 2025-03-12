# MySQL协议

MySQL协议是建立在tcp协议上的私有协议，用于MySQL客户端和服务器进行数据交互。  

## MySQL协议段

MySQL协议中数据被封装进MySQL Protocol中，一个tcp报文中允许存在多个MySQL Protocol。  
每个MySQL Protocol由3部分组成:

1. Packet Length: 前3个字节，用于标识Payload部分的长度(小端序)
2. Packet Number：第4个字节，表示MySQL协议段的序号，从0开始
3. Payload: MySQL协议段中的主体部分，根据不同阶段结构也不同

## MySQL认证阶段

1. 客户端首先跟MySQL端口建立连接，然后客户端发送一个不带MySQL协议段的tcp报文，服务端返回一个带有MySQL基础信息的报文，Packet Number为0，其结构体为:

   ```cpp
    typedef struct{
        int         header;                         // Packet Length + Packet Number
        char        protocol;                       // 协议版本号
        char*       version;                        // MySQL版本号
        int         thread;                         // 服务器线程id
        long long   salt1;                          // 随机盐值(第一部分)
        short       server_capabilities;            // 服务器权能标志
        char        language;                       // 服务器字符编码
        short       server_status;                  // 服务器状态标志
        short       extended_server_capabilities;   // 服务器拓展权能标志
        char        authentication_plugin_length;   // 身份验证插件长度
        char[10]    unused;                         // 未使用区域，用0填充
        char*       salt2;                          // 随机盐值(第二部分)，至少12字节
        char*       authentication_plugin;          // 身份验证插件名称
    }server_greeting;
   ```

2. 客户端发送一个带有MySQL连接信息的报文，Packet Number为1
3. 服务端返回连接确认信息，如果成功的话，返回OK Packet的MySQL协议段，Packet Number为2

> 认证阶段结束后Packet Number清0

## 查询阶段

客户端发起查询报文，MySQL协议段中第5个字节为3，代表Query操作，每次查询报文中Packet Number从0开始
服务端针对查询报文，有4种响应结果:

* OK Packet: 正确响应包，其结构体为:

    ```cpp
    typedef struct{
        int      header;            // Packet Length + Packet Number
        char     response_code      // 响应标识符
        char     affected_rows;     // 受影响的行数
        char     last_insert_id;    // 固定填充为0x00
        short    server_status;     // 服务器状态标识符
        short    warning_count;     // 警告数
    }OK_Packet;
    ```

* ProtocolText::Resultset：结果集，返回查询的结果，包含多个MySQL协议段
  * column count: 固定5字节，第5个字节表示字段包的数量
  * field packet(数组): 字段包中包含查询结果集字段的信息，其结构体为:

    ```cpp
    typedef struct {
        int    header;            // Packet Length + Packet Number
        char   catalog_len;       // Catalog名称长度
        char*  catalog;           // Catalog名称
        char   db_name_len;       // 数据库名长度
        char*  db_name;           // 数据库名称
        char   table_name_len;    // 表名长度
        char*  table_name;        // 表名
        char   org_table_len;     // 原始表名长度（通常与table_name相同）
        char*  org_table;         // 原始表名（物理表名）
        char   col_name_len;      // 列名长度
        char*  col_name;          // 列别名
        char   org_col_name_len;  // 原始列名长度
        char*  org_col_name;      // 原始列名（物理列名）
        char   filler1;           // 固定0x0C填充
        short  charset;           // 字符集编号
        int    col_length;        // 列最大长度
        char   col_type;          // 列在MySQL中的数据类型,0xfc为FIELD_TYPE_BLOB，0xf9为FIELD_TYPE_TINY_BLOB，如果是这两个，可以触发Jdbc的反序列化
        short  flags;             // 列标志，jdbc反序列化中需要满足BINARY_FLAG | BLOB_FLAG
        char   decimals;          // 小数位数
        short  filler2;           // 固定0x0000填充
    } MySQLFieldPacket;
    ```

  * row packet(数组): 行包中包含查询结果行的信息，其结构体为:

    ```cpp
    typedef struct {
        int    header;                 // Packet Length + Packet Number
        struct {
            char[1-8]   result_len;    // 查询结果的长度
                                       /* 
                                            如果length=0，该字段直接使用单字节0xFB表示
                                            如果0<length<251，用1字节表示长度;
                                            如果251<=length<2^16，用0xfc + 2字节;
                                            如果2^16<= length< 2^24，用0xfd + 3字节;
                                            如果length>= 2^24，用0xfe+8字节
                                       */
            char*  result;             // 查询结果
        }result;
    } MySQLRowPacket;
    ```

    >result的数量和字段数量一样

  * EOF包,用于标识row packet数组的结束，需要第5个字节为0xFE并且包的长度小于9字节,结构体和OK Packet一致
