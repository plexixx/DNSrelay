#include "dns.h"
#include "simlist.h"

IDtrans IDtransformer[MAX_IDLIST_LENGTH];

int debug_level = 0;
char DNS_Server_IP[16] = "10.3.9.45"; //外部服务器

int ID_Count = 0; //转换单元计数器
WSADATA wsaData;
SOCKET my_socket;

//struct sockaddr_in client_from, server_from;
struct sockaddr_in client, server;
int length_client = sizeof(client);

nodeptr url_ip_table; /* 域名IP地址映射表 */
nodeptr cache;        /* 高速缓存 */


void input(int argc, char* argv[])      /* 处理控制台参数 */
{
    int userSetServer = 0;

    /* “”， “-d”,"-dd", "-ddd"*/

    if (argc > 1 && argv[1][0] == '-')
    {
        //确定debug等级
        if (argv[1][1] == 'd') debug_level++;
        if (argv[1][2] == 'd') debug_level++;
        if (argc > 2)
        {
            //设置服务器地址
            userSetServer = 1;
            strcpy(DNS_Server_IP, argv[2]);
        }
    }
    /*是否应加入其他文件的读取*/
    if (userSetServer)
        printf("设置的服务器地址 : %s\n", argv[2]);
    else
        printf("设置为默认服务器，地址 : %s\n", DNS_Server_IP);
    printf("Debug 等级 : %d\n", debug_level);
}

/* 根据txt文件读取域名-ip映射表 */
void readFile()
{
    FILE* file;
    if ((file = fopen("dnsrelay.txt", "r")) == NULL) //读取文件失败
    {
        if (debug_level > 1)
            printf("Unable to read dnsrelay.txt\n");
        return;
    }

    char url[65] = "", ip[16] = "";
    char buf[MAX_BUF_LENGTH];

    while (fgets(buf, MAX_BUF_LENGTH, file))
    {
        if (sscanf(buf, "%16s %64s", ip, url) != 2)
        {
            fclose(file);
            return;
        }
        if (debug_level >= 1)
            printf("Read from 'dnsrelay.txt' -> [Url : %s, IP : %s]\n", url, ip);

        url_ip_table = push_front(url_ip_table, url, ip); /* 添加至域名_IP映射表中 */
    }

    fclose(file);
}

/* 初始化ID转换表 */
void initIDTable()
{
    for (int i = 0; i < MAX_IDLIST_LENGTH; i++) {
        IDtransformer[i].old_id = 0;
        IDtransformer[i].finished = TRUE;
        IDtransformer[i].survival_time = 0;
        memset(&(IDtransformer[i].client_addr), 0, sizeof(SOCKADDR_IN));
    }
}

/* 初始化套接字信息 */
void initSocket()
{
    /* 建立套接字 */
    my_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (my_socket < 0)
    {
        if (debug_level >= 1)
            printf("套接字建立失败\n");
        exit(1);
    }

    printf("套接字建立成功\n");

    /* 将套接字发送、接受模式设置为非阻塞模式 */
    int non_block = 1;
    ioctlsocket(my_socket, FIONBIO, (u_long FAR*) & non_block);


    client.sin_family = AF_INET;/* IPv4 */
    client.sin_addr.s_addr = INADDR_ANY;/* 本地IP地址随机 */
    client.sin_port = htons(DNS_PORT);/* 绑定到指定端口 */

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(DNS_Server_IP);/* 绑定到外部服务器 */
    server.sin_port = htons(DNS_PORT);


    /* 本地端口号，通用端口号，允许复用 */
    int reuse = 0;
    setsockopt(my_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    /* 将端口号与socket关联 */
    if (bind(my_socket, (struct sockaddr*)&client, sizeof(client)) < 0) {
        printf("套接字端口绑定失败\n");
        exit(1);
    }

    if (debug_level > 1)
        printf("套接字端口绑定成功\n");
}

/* 更新cache内容 */
void addRecordToCache(char* url, char* ip)
{
    char tmp[100];
    memset(tmp, '\0', sizeof(tmp));
    strcpy(tmp, get_ip(cache, url));

    /* 判断cache中是否存在传入域名 */

    /* 若查到域名，更新ip */
    if (strcmp(tmp, "404_NOT_FOUND") != 0)
    {
        nodeptr cur = cache;
        while (strcmp(cur->url, url) != 0)
        {
            cur = cur->next;
        }

        for (int i = 0; i < cur->num; i++)
        {
            /* 若cache中已存在映射关系，直接返回 */
            if (strcmp(cur->ip[i], ip) == 0)
                return;
        }
        if (cur->num > 20) //cache中最多存储20个映射
            return;

        strcpy(cache->ip[cur->num++], ip); //添加映射关系
    }
    else
    {
        if (size(cache) >= MAX_CACHE_SIZE) // cache已满
        {
            cache = pop_back(cache); // 删除最早使用的内容
        }
        cache = push_front(cache, url, ip);
        if (debug_level > 1)
            outCache();
    }
}

/* 输出cache详细内容 */
void outCache()
{
    printf("\n\n--------------  Cache  --------------\n");
    print_list(cache);
}

/* 输出完整的数据包信息 */
void outPacket(char* buf, int len)
{
    unsigned char byte;
    printf("包长 = %d\n\n", len);
    printf("数据包内容:\n");
    for (int i = 0; i < len;) {
        byte = (unsigned char)buf[i];
        printf("%02x ", byte);
        i++;
        if (i % 16 == 0) //每行只打印16字节
            printf("\n");
    }
}

/* 分配新ID */
unsigned short addNewID(unsigned short ID, SOCKADDR_IN client_from, BOOL finished)
{
    int i = 0;
    for (i = 0; i != MAX_IDLIST_LENGTH; ++i) {
        /* 寻找超时失效或者已完成的位置 */
        if ((IDtransformer[i].survival_time > 0 && IDtransformer[i].survival_time < time(NULL)) ||
            IDtransformer[i].finished == TRUE)
        {
            /* 确保新旧ID不同 */
            if (IDtransformer[i].old_id != i + 1)
            {
                IDtransformer[i].old_id = ID;               //设置ID
                IDtransformer[i].client_addr = client_from; //设置客户端套接字
                IDtransformer[i].finished = finished;       //标记查询是否完成
                IDtransformer[i].survival_time = (int)time(NULL) + ID_EXPIRE_TIME; //时间设置为1000秒 ///

                break;
            }
        }
    }

    /* 当前转换表已满,登记失败 */
    if (i == MAX_IDLIST_LENGTH)
        return 0;

    return (unsigned short)i + 1; //返回新ID号
}

/* DNS QName转换 */
void nameTranslate(char* buf, char* result)
{
    int i = 0, j = 0, k = 0, len = strlen(buf);
    while (i < len) {
        if (buf[i] > 0 && buf[i] <= 63) //计数
        {
            for (j = buf[i], i++; j > 0; j--, i++, k++) //复制url
            {
                result[k] = buf[i];
            }
        }
        if (buf[i] != 0) //如果还没结束，加个"."做分隔符
        {
            result[k] = '.';
            k++;
        }
    }
    result[k] = '\0'; //添加结束符
}

/* 收到来自服务器的信息 */
void receiveFromExtern(char* buf, int len, SOCKADDR_IN server_addr)
{
    char url[200];

    if (debug_level > 1) {
        outPacket(buf, len);
    }

    //从接收报文中获取ID号
    unsigned short ID;
    memcpy(&ID, buf, sizeof(unsigned short));
    int cur_id = ID - 1;

    //从ID映射表查找原来的ID号
    memcpy(buf, &IDtransformer[cur_id].old_id, sizeof(unsigned short));
    IDtransformer[cur_id].finished = TRUE;

    //获取客户端信息
    SOCKADDR_IN client_temp = IDtransformer[cur_id].client_addr;

    /*响应报文header格式
      0	 1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |					   ID
    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z	|	RCODE	|
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |					 QDCOUNT
    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |					 ANCOUNT
    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |					 NSCOUNT
    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |					 ARCOUNT
    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    //问题数QDCOUNT 无符号16位整数表示报文请求段中的问题记录数。
    //资源记录数ANCOUNT 无符号16位整数表示报文回答段中的回答记录数。

    int num_query = ntohs(*((unsigned short*)(buf + 4)));
    int num_response = ntohs(*((unsigned short*)(buf + 6)));

    char* p = buf + 12; //将p指向question字段

    //读取question字段所有的url
    /*question格式
      0	 1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |					  QNAME
    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |					  QTYPE
    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |					 QCLASS |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    for (int i = 0; i < num_query; i++) {
        nameTranslate(p, url);
        while (*p > 0) {
            p += (*p) + 1;
        }
        p += 5; //指向下一个Queries区域，
        /*结构：查询名（最长63字节+'\0'）+查询类型（2字节）+查询类（2字节）*/
    }

    if (num_response > 0 && debug_level > 1) {
        printf("来自外部DNS服务器: <Url : %s>\n", url);
    }

    //分析外部DNS服务器的回应

    for (int i = 0; i < num_response; ++i) {
        if ((unsigned char)*p == 0xc0) /* 表明NAME域使用指针偏移表示 */
        {
            p += 2;
        }
        else {
            while (*p > 0) {
                p += (*p) + 1;
            }
            ++p;
        }
        //网络字节是从低字节到高字节的（例如0001），而主机字节顺序从高字节到低字节（对应0100）
        // ntohs：将网络字节顺序转换为主机字节顺序
        // htons: 将主机字节顺序转换为网络字节顺序

        //获取资源记录域的各个字段
        unsigned short type = ntohs(*(unsigned short*)p); // TYPE字段
        p += sizeof(unsigned short);
        unsigned short _class = ntohs(*(unsigned short*)p); // CLASS字段
        p += sizeof(unsigned short);
        unsigned short ttl_high_byte = ntohs(*(unsigned short*)p); // TTL高位字节
        p += sizeof(unsigned short);
        unsigned short ttl_low_byte = ntohs(*(unsigned short*)p); // TTL低位字节
        p += sizeof(unsigned short);
        int ttl =
            (((int)ttl_high_byte) << 16) | ttl_low_byte; //合并成正常的int类型数据

        int rdlength = ntohs(*(unsigned short*)p); //数据长度
        //对类型1（TYPE A记录）资源数据是4字节的IP地址
        p += sizeof(unsigned short);

        if (debug_level > 1) {
            printf("Type: %d,  Class: %d,  TTL: %d\n", type, _class, ttl);
        }

        char ip[16];
        int ip1, ip2, ip3, ip4;

        // 类型：A，由域名获得IPv4地址
        if (type == 1) {
            ip1 = (unsigned char)*p++;
            ip2 = (unsigned char)*p++;
            ip3 = (unsigned char)*p++;
            ip4 = (unsigned char)*p++;
            sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);

            if (debug_level > 1) {
                printf("IP Address: %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
            }

            addRecordToCache(url, ip);

            while (p && *(p + 1) &&
                *(p += 12)) //获取服务器发来报文的IP地址，跳过前面的12字节
            {
                ip1 = (unsigned char)*p++;
                ip2 = (unsigned char)*p++;
                ip3 = (unsigned char)*p++;
                ip4 = (unsigned char)*p++;
                sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);

                if (debug_level > 1) {
                    printf("IP Address: %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
                }

                //将映射加入到cache映射表
                addRecordToCache(url, ip);
            }
            break;
        }
        else {
            p += rdlength;
        }
    }

    /*
     *  将包送回客户端
     *  sendto()函数：发送一个数据报，数据在buf中，需要提供地址
     *
     *  local_socket：外部服务器套接字
     *  buf：发送数据缓冲区
     *  sizeof(buf)：接收缓冲区大小
     *  0：标志位flag，表示调用操作方式，默认设为0
     *  client：目标数据发送源地址
     *  sizeof(client)：地址大小
     *  返回值：len：成功接收到的数据的字符数（长度），接收失败返回SOCKET_ERROR(-1)
     */
    len = sendto(my_socket, buf, len, 0, (SOCKADDR*)&client_temp,
        sizeof(client_temp));
}

/* 收到来自客户端的信息 */
void receiveFromLocal(char* buf, int len, SOCKADDR_IN client_addr)
{
    int out_cache_flag = 0;  //是否打印cache的标志
    char old_url[200];       //转换前的url
    char new_url[200];       //转换后的url

    memcpy(old_url, &(buf[12]), len); //从报文中获得url,报头长度12字节
    nameTranslate(old_url, new_url);     // url转换

    int i = 0;

    while (*(buf + 12 + i)) {
        i++;
    }
    i++;

    if (buf + 12 + i != NULL) {
        unsigned short type = ntohs(*(unsigned short*)(buf + 12 + i)); // TYPE字段
        if (type == 28 && strcmp(get_ip(url_ip_table, new_url), "0.0.0.0") != 0) { //如果是IPv6类型且未被屏蔽
            unsigned short ID;
            memcpy(&ID, buf, sizeof(unsigned short));
            unsigned short new_id =
                addNewID(ID, client_addr, FALSE); //将原id存入id转换表

            if (new_id == 0) {
                if (debug_level > 1) {
                    printf("Failed to add new ID, local ID table is full！\n");
                }
            }
            else {
                memcpy(buf, &new_id, sizeof(unsigned short));
                len = sendto(my_socket, buf, len, 0,
                    (struct sockaddr*)&server, sizeof(server));
                //将域名查询请求发送至外部dns服务器
                if (debug_level > 1) {
                    printf("<Domain Name: %s>\n\n", new_url);
                }
            }
            return;
        }
    }

    if (debug_level > 1)
        printf("\n\n---- 收到了客户端的消息: [IP:%s]----\n",
            inet_ntoa(client_addr.sin_addr));

    if (debug_level) {
        //打印时间戳
        time_t t = time(NULL);
        char temp[64];
        strftime(temp, sizeof(temp), "%Y/%m/%d %X %A", localtime(&t));
        printf("%s\t#%d\n", temp, ID_Count++);
    }

    char ip[100];
    char table_result[200];
    char cache_result[200];
    strcpy(table_result,
        get_ip(url_ip_table, new_url)); //从映射表中查询到的ip地址结果
    strcpy(cache_result, get_ip(cache, new_url)); //从cache中查询到的IP地址结果

    //从本地映射表中查询是否有该记录
    if (strcmp(table_result, "404_NOT_FOUND") == 0 &&
        strcmp(cache_result, "404_NOT_FOUND") == 0) //若域名在本地文件、cache中无法找到，需要上报外部dns服务器
    {

        unsigned short ID;
        memcpy(&ID, buf, sizeof(unsigned short));
        unsigned short new_id =
            addNewID(ID, client_addr, FALSE); //将原id存入id转换表

        if (new_id == 0) {
            if (debug_level > 1) {
                printf("Failed to add new ID, local ID table is full！\n");
            }
        }
        else {
            memcpy(buf, &new_id, sizeof(unsigned short));
            len = sendto(my_socket, buf, len, 0,
                (struct sockaddr*)&server, sizeof(server));
            //将域名查询请求发送至外部dns服务器
            if (debug_level > 0) {
                printf("<Domain Name: %s>\n\n", new_url);
            }
        }
    }
    else //若在本地查询到了域名和ip的映射
    {
        if (strcmp(table_result, "404_NOT_FOUND") != 0) //如果是从映射表中查到
        {
            strcpy(ip, table_result);
            if (debug_level > 0) {
                if (debug_level > 1)
                    printf("The record is in the Url-IP map\n");
                printf("<Domain Name: %s , IP Address: %s>\n\n", new_url, ip);
            }
        }
        else //如果是从cache中查到
        {
            strcpy(ip, cache_result);
            cache = move_to_head(cache, new_url); //将记录移到靠前的位置

            if (debug_level > 0) {
                if (debug_level > 1)
                    printf("The record is in the cache\n");
                printf("<Domain Name: %s , IP: %s>\n\n", new_url, ip);
                out_cache_flag = 1;
            }
        }

        char sendbuf[MAX_BUF_LENGTH];
        memcpy(sendbuf, buf, len); //开始构造数据包

        /*响应报文header格式
          0	 1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |					   ID
        |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z	|	RCODE	|
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |					 QDCOUNT
        |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |					 ANCOUNT
        |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |					 NSCOUNT
        |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |					 ARCOUNT
        |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         */
         // QR为1表示响应报
         // OPCODE为0表示标准查询(QUERY)
         // AA（权威答案）为0表示应答服务器不是该域名的权威解析服务器
         // TC为0表示报文未被截断
         // RD（期望递归）为1表示希望采用递归查询
         // RA（递归可用）为1表示名字服务器支持递归查询
         // Z为0，作为保留字段
         // RCODE为0，表示没有差错
         //因此报文头部的第3-4字节为值8180

        unsigned short num;

        if (strcmp(ip, "0.0.0.0") == 0) //判断此ip是否应该被墙
        {
            num = htons(0x8183);
            memcpy(&sendbuf[2], &num, sizeof(unsigned short));
        }
        else {
            num = htons(0x8180);
            memcpy(&sendbuf[2], &num, sizeof(unsigned short));
        }

        if (strcmp(ip, "0.0.0.0") == 0) //判断此ip是否应该被墙
        {

            num = htons(0x0); //设置回答数为0
        }
        else {
            num = htons(0x1); //否则设置回答数为1
        }
        memcpy(&sendbuf[6], &num, sizeof(unsigned short));

        /*构造DNS报文资源记录（RR）区域
          0	 1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |
        | /
        / /					  NAME
        / |
        |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |					  TYPE
        |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |					 CLASS
        |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |					  TTL
        |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |					RDLENGTH
        |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        /					 RDATA
        / /
        /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        */

        int pos = 0;
        char res_rec[16];

        // NAME字段：资源记录中的域名通常是查询问题部分的域名的重复，可以使用2字节的偏移指针表示
        //最高2位为11，用于识别指针，最后四位为1100（12）表示头部长度
        //因此该字段的值为0xC00C
        unsigned short name = htons(0xc00c);
        memcpy(res_rec, &name, sizeof(unsigned short));
        pos += sizeof(unsigned short);

        // TYPE字段：资源记录的类型，1表示IPv4地址
        unsigned short type = htons(0x0001);
        memcpy(res_rec + pos, &type, sizeof(unsigned short));
        pos += sizeof(unsigned short);

        // CLASS字段：查询类，通常为1（IN），代表Internet数据
        unsigned short _class = htons(0x0001);
        memcpy(res_rec + pos, &_class, sizeof(unsigned short));
        pos += sizeof(unsigned short);

        // TTL字段：资源记录生存时间（待修改）
        unsigned long ttl = htonl(0x00000080);
        memcpy(res_rec + pos, &ttl, sizeof(unsigned long));
        pos += sizeof(unsigned long);

        // RDLENGTH字段：资源数据长度，对类型1（TYPE A记录）资源数据是4字节的IP地址
        unsigned short RDlength = htons(0x0004);
        memcpy(res_rec + pos, &RDlength, sizeof(unsigned short));
        pos += sizeof(unsigned short);

        // RDATA字段：这里是一个IP地址
        unsigned long IP = (unsigned long)inet_addr(ip);
        memcpy(res_rec + pos, &IP, sizeof(unsigned long));
        pos += sizeof(unsigned long);
        pos += len;

        //请求报文和响应部分共同组成DNS响应报文存入sendbuf
        memcpy(sendbuf + len, res_rec, sizeof(res_rec));

        len = sendto(my_socket, sendbuf, pos, 0, (SOCKADDR*)&client_addr,
            sizeof(client_addr));
        //将构造好的报文段发给客户端

        if (len < 0 && debug_level > 1) {
            printf("Failed to send message to client\n");
        }

        char* p;
        p = sendbuf + len - 4;
        if (debug_level > 1) {
            printf("Send message: <Domain Name: %s ，IP: %u.%u.%u.%u>\n", new_url,
                (unsigned char)*p, (unsigned char)*(p + 1),
                (unsigned char)*(p + 2), (unsigned char)*(p + 3));
        }
        if (out_cache_flag && debug_level > 1) {
            outCache();
        }
    }
}