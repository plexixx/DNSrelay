#include "dns.h"
#include "simlist.h"

IDtrans IDtransformer[MAX_IDLIST_LENGTH];

int debug_level = 0;
char DNS_Server_IP[16] = "10.3.9.45"; //�ⲿ������

int ID_Count = 0; //ת����Ԫ������
WSADATA wsaData;
SOCKET my_socket;

//struct sockaddr_in client_from, server_from;
struct sockaddr_in client, server;
int length_client = sizeof(client);

nodeptr url_ip_table; /* ����IP��ַӳ��� */
nodeptr cache;        /* ���ٻ��� */


void input(int argc, char* argv[])      /* �������̨���� */
{
    int userSetServer = 0;

    /* ������ ��-d��,"-dd", "-ddd"*/

    if (argc > 1 && argv[1][0] == '-')
    {
        //ȷ��debug�ȼ�
        if (argv[1][1] == 'd') debug_level++;
        if (argv[1][2] == 'd') debug_level++;
        if (argc > 2)
        {
            //���÷�������ַ
            userSetServer = 1;
            strcpy(DNS_Server_IP, argv[2]);
        }
    }
    /*�Ƿ�Ӧ���������ļ��Ķ�ȡ*/
    if (userSetServer)
        printf("���õķ�������ַ : %s\n", argv[2]);
    else
        printf("����ΪĬ�Ϸ���������ַ : %s\n", DNS_Server_IP);
    printf("Debug �ȼ� : %d\n", debug_level);
}

/* ����txt�ļ���ȡ����-ipӳ��� */
void readFile()
{
    FILE* file;
    if ((file = fopen("dnsrelay.txt", "r")) == NULL) //��ȡ�ļ�ʧ��
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

        url_ip_table = push_front(url_ip_table, url, ip); /* ���������_IPӳ����� */
    }

    fclose(file);
}

/* ��ʼ��IDת���� */
void initIDTable()
{
    for (int i = 0; i < MAX_IDLIST_LENGTH; i++) {
        IDtransformer[i].old_id = 0;
        IDtransformer[i].finished = TRUE;
        IDtransformer[i].survival_time = 0;
        memset(&(IDtransformer[i].client_addr), 0, sizeof(SOCKADDR_IN));
    }
}

/* ��ʼ���׽�����Ϣ */
void initSocket()
{
    /* �����׽��� */
    my_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (my_socket < 0)
    {
        if (debug_level >= 1)
            printf("�׽��ֽ���ʧ��\n");
        exit(1);
    }

    printf("�׽��ֽ����ɹ�\n");

    /* ���׽��ַ��͡�����ģʽ����Ϊ������ģʽ */
    int non_block = 1;
    ioctlsocket(my_socket, FIONBIO, (u_long FAR*) & non_block);


    client.sin_family = AF_INET;/* IPv4 */
    client.sin_addr.s_addr = INADDR_ANY;/* ����IP��ַ��� */
    client.sin_port = htons(DNS_PORT);/* �󶨵�ָ���˿� */

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(DNS_Server_IP);/* �󶨵��ⲿ������ */
    server.sin_port = htons(DNS_PORT);


    /* ���ض˿ںţ�ͨ�ö˿ںţ������� */
    int reuse = 0;
    setsockopt(my_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    /* ���˿ں���socket���� */
    if (bind(my_socket, (struct sockaddr*)&client, sizeof(client)) < 0) {
        printf("�׽��ֶ˿ڰ�ʧ��\n");
        exit(1);
    }

    if (debug_level > 1)
        printf("�׽��ֶ˿ڰ󶨳ɹ�\n");
}

/* ����cache���� */
void addRecordToCache(char* url, char* ip)
{
    char tmp[100];
    memset(tmp, '\0', sizeof(tmp));
    strcpy(tmp, get_ip(cache, url));

    /* �ж�cache���Ƿ���ڴ������� */

    /* ���鵽����������ip */
    if (strcmp(tmp, "404_NOT_FOUND") != 0)
    {
        nodeptr cur = cache;
        while (strcmp(cur->url, url) != 0)
        {
            cur = cur->next;
        }

        for (int i = 0; i < cur->num; i++)
        {
            /* ��cache���Ѵ���ӳ���ϵ��ֱ�ӷ��� */
            if (strcmp(cur->ip[i], ip) == 0)
                return;
        }
        if (cur->num > 20) //cache�����洢20��ӳ��
            return;

        strcpy(cache->ip[cur->num++], ip); //���ӳ���ϵ
    }
    else
    {
        if (size(cache) >= MAX_CACHE_SIZE) // cache����
        {
            cache = pop_back(cache); // ɾ������ʹ�õ�����
        }
        cache = push_front(cache, url, ip);
        if (debug_level > 1)
            outCache();
    }
}

/* ���cache��ϸ���� */
void outCache()
{
    printf("\n\n--------------  Cache  --------------\n");
    print_list(cache);
}

/* ������������ݰ���Ϣ */
void outPacket(char* buf, int len)
{
    unsigned char byte;
    printf("���� = %d\n\n", len);
    printf("���ݰ�����:\n");
    for (int i = 0; i < len;) {
        byte = (unsigned char)buf[i];
        printf("%02x ", byte);
        i++;
        if (i % 16 == 0) //ÿ��ֻ��ӡ16�ֽ�
            printf("\n");
    }
}

/* ������ID */
unsigned short addNewID(unsigned short ID, SOCKADDR_IN client_from, BOOL finished)
{
    int i = 0;
    for (i = 0; i != MAX_IDLIST_LENGTH; ++i) {
        /* Ѱ�ҳ�ʱʧЧ��������ɵ�λ�� */
        if ((IDtransformer[i].survival_time > 0 && IDtransformer[i].survival_time < time(NULL)) ||
            IDtransformer[i].finished == TRUE)
        {
            /* ȷ���¾�ID��ͬ */
            if (IDtransformer[i].old_id != i + 1)
            {
                IDtransformer[i].old_id = ID;               //����ID
                IDtransformer[i].client_addr = client_from; //���ÿͻ����׽���
                IDtransformer[i].finished = finished;       //��ǲ�ѯ�Ƿ����
                IDtransformer[i].survival_time = (int)time(NULL) + ID_EXPIRE_TIME; //ʱ������Ϊ1000�� ///

                break;
            }
        }
    }

    /* ��ǰת��������,�Ǽ�ʧ�� */
    if (i == MAX_IDLIST_LENGTH)
        return 0;

    return (unsigned short)i + 1; //������ID��
}

/* DNS QNameת�� */
void nameTranslate(char* buf, char* result)
{
    int i = 0, j = 0, k = 0, len = strlen(buf);
    while (i < len) {
        if (buf[i] > 0 && buf[i] <= 63) //����
        {
            for (j = buf[i], i++; j > 0; j--, i++, k++) //����url
            {
                result[k] = buf[i];
            }
        }
        if (buf[i] != 0) //�����û�������Ӹ�"."���ָ���
        {
            result[k] = '.';
            k++;
        }
    }
    result[k] = '\0'; //��ӽ�����
}

/* �յ����Է���������Ϣ */
void receiveFromExtern(char* buf, int len, SOCKADDR_IN server_addr)
{
    char url[200];

    if (debug_level > 1) {
        outPacket(buf, len);
    }

    //�ӽ��ձ����л�ȡID��
    unsigned short ID;
    memcpy(&ID, buf, sizeof(unsigned short));
    int cur_id = ID - 1;

    //��IDӳ������ԭ����ID��
    memcpy(buf, &IDtransformer[cur_id].old_id, sizeof(unsigned short));
    IDtransformer[cur_id].finished = TRUE;

    //��ȡ�ͻ�����Ϣ
    SOCKADDR_IN client_temp = IDtransformer[cur_id].client_addr;

    /*��Ӧ����header��ʽ
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
    //������QDCOUNT �޷���16λ������ʾ����������е������¼����
    //��Դ��¼��ANCOUNT �޷���16λ������ʾ���Ļش���еĻش��¼����

    int num_query = ntohs(*((unsigned short*)(buf + 4)));
    int num_response = ntohs(*((unsigned short*)(buf + 6)));

    char* p = buf + 12; //��pָ��question�ֶ�

    //��ȡquestion�ֶ����е�url
    /*question��ʽ
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
        p += 5; //ָ����һ��Queries����
        /*�ṹ����ѯ�����63�ֽ�+'\0'��+��ѯ���ͣ�2�ֽڣ�+��ѯ�ࣨ2�ֽڣ�*/
    }

    if (num_response > 0 && debug_level > 1) {
        printf("�����ⲿDNS������: <Url : %s>\n", url);
    }

    //�����ⲿDNS�������Ļ�Ӧ

    for (int i = 0; i < num_response; ++i) {
        if ((unsigned char)*p == 0xc0) /* ����NAME��ʹ��ָ��ƫ�Ʊ�ʾ */
        {
            p += 2;
        }
        else {
            while (*p > 0) {
                p += (*p) + 1;
            }
            ++p;
        }
        //�����ֽ��Ǵӵ��ֽڵ����ֽڵģ�����0001�����������ֽ�˳��Ӹ��ֽڵ����ֽڣ���Ӧ0100��
        // ntohs���������ֽ�˳��ת��Ϊ�����ֽ�˳��
        // htons: �������ֽ�˳��ת��Ϊ�����ֽ�˳��

        //��ȡ��Դ��¼��ĸ����ֶ�
        unsigned short type = ntohs(*(unsigned short*)p); // TYPE�ֶ�
        p += sizeof(unsigned short);
        unsigned short _class = ntohs(*(unsigned short*)p); // CLASS�ֶ�
        p += sizeof(unsigned short);
        unsigned short ttl_high_byte = ntohs(*(unsigned short*)p); // TTL��λ�ֽ�
        p += sizeof(unsigned short);
        unsigned short ttl_low_byte = ntohs(*(unsigned short*)p); // TTL��λ�ֽ�
        p += sizeof(unsigned short);
        int ttl =
            (((int)ttl_high_byte) << 16) | ttl_low_byte; //�ϲ���������int��������

        int rdlength = ntohs(*(unsigned short*)p); //���ݳ���
        //������1��TYPE A��¼����Դ������4�ֽڵ�IP��ַ
        p += sizeof(unsigned short);

        if (debug_level > 1) {
            printf("Type: %d,  Class: %d,  TTL: %d\n", type, _class, ttl);
        }

        char ip[16];
        int ip1, ip2, ip3, ip4;

        // ���ͣ�A�����������IPv4��ַ
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
                *(p += 12)) //��ȡ�������������ĵ�IP��ַ������ǰ���12�ֽ�
            {
                ip1 = (unsigned char)*p++;
                ip2 = (unsigned char)*p++;
                ip3 = (unsigned char)*p++;
                ip4 = (unsigned char)*p++;
                sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);

                if (debug_level > 1) {
                    printf("IP Address: %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
                }

                //��ӳ����뵽cacheӳ���
                addRecordToCache(url, ip);
            }
            break;
        }
        else {
            p += rdlength;
        }
    }

    /*
     *  �����ͻؿͻ���
     *  sendto()����������һ�����ݱ���������buf�У���Ҫ�ṩ��ַ
     *
     *  local_socket���ⲿ�������׽���
     *  buf���������ݻ�����
     *  sizeof(buf)�����ջ�������С
     *  0����־λflag����ʾ���ò�����ʽ��Ĭ����Ϊ0
     *  client��Ŀ�����ݷ���Դ��ַ
     *  sizeof(client)����ַ��С
     *  ����ֵ��len���ɹ����յ������ݵ��ַ��������ȣ�������ʧ�ܷ���SOCKET_ERROR(-1)
     */
    len = sendto(my_socket, buf, len, 0, (SOCKADDR*)&client_temp,
        sizeof(client_temp));
}

/* �յ����Կͻ��˵���Ϣ */
void receiveFromLocal(char* buf, int len, SOCKADDR_IN client_addr)
{
    int out_cache_flag = 0;  //�Ƿ��ӡcache�ı�־
    char old_url[200];       //ת��ǰ��url
    char new_url[200];       //ת�����url

    memcpy(old_url, &(buf[12]), len); //�ӱ����л��url,��ͷ����12�ֽ�
    nameTranslate(old_url, new_url);     // urlת��

    int i = 0;

    while (*(buf + 12 + i)) {
        i++;
    }
    i++;

    if (buf + 12 + i != NULL) {
        unsigned short type = ntohs(*(unsigned short*)(buf + 12 + i)); // TYPE�ֶ�
        if (type == 28 && strcmp(get_ip(url_ip_table, new_url), "0.0.0.0") != 0) { //�����IPv6������δ������
            unsigned short ID;
            memcpy(&ID, buf, sizeof(unsigned short));
            unsigned short new_id =
                addNewID(ID, client_addr, FALSE); //��ԭid����idת����

            if (new_id == 0) {
                if (debug_level > 1) {
                    printf("Failed to add new ID, local ID table is full��\n");
                }
            }
            else {
                memcpy(buf, &new_id, sizeof(unsigned short));
                len = sendto(my_socket, buf, len, 0,
                    (struct sockaddr*)&server, sizeof(server));
                //��������ѯ���������ⲿdns������
                if (debug_level > 1) {
                    printf("<Domain Name: %s>\n\n", new_url);
                }
            }
            return;
        }
    }

    if (debug_level > 1)
        printf("\n\n---- �յ��˿ͻ��˵���Ϣ: [IP:%s]----\n",
            inet_ntoa(client_addr.sin_addr));

    if (debug_level) {
        //��ӡʱ���
        time_t t = time(NULL);
        char temp[64];
        strftime(temp, sizeof(temp), "%Y/%m/%d %X %A", localtime(&t));
        printf("%s\t#%d\n", temp, ID_Count++);
    }

    char ip[100];
    char table_result[200];
    char cache_result[200];
    strcpy(table_result,
        get_ip(url_ip_table, new_url)); //��ӳ����в�ѯ����ip��ַ���
    strcpy(cache_result, get_ip(cache, new_url)); //��cache�в�ѯ����IP��ַ���

    //�ӱ���ӳ����в�ѯ�Ƿ��иü�¼
    if (strcmp(table_result, "404_NOT_FOUND") == 0 &&
        strcmp(cache_result, "404_NOT_FOUND") == 0) //�������ڱ����ļ���cache���޷��ҵ�����Ҫ�ϱ��ⲿdns������
    {

        unsigned short ID;
        memcpy(&ID, buf, sizeof(unsigned short));
        unsigned short new_id =
            addNewID(ID, client_addr, FALSE); //��ԭid����idת����

        if (new_id == 0) {
            if (debug_level > 1) {
                printf("Failed to add new ID, local ID table is full��\n");
            }
        }
        else {
            memcpy(buf, &new_id, sizeof(unsigned short));
            len = sendto(my_socket, buf, len, 0,
                (struct sockaddr*)&server, sizeof(server));
            //��������ѯ���������ⲿdns������
            if (debug_level > 0) {
                printf("<Domain Name: %s>\n\n", new_url);
            }
        }
    }
    else //���ڱ��ز�ѯ����������ip��ӳ��
    {
        if (strcmp(table_result, "404_NOT_FOUND") != 0) //����Ǵ�ӳ����в鵽
        {
            strcpy(ip, table_result);
            if (debug_level > 0) {
                if (debug_level > 1)
                    printf("The record is in the Url-IP map\n");
                printf("<Domain Name: %s , IP Address: %s>\n\n", new_url, ip);
            }
        }
        else //����Ǵ�cache�в鵽
        {
            strcpy(ip, cache_result);
            cache = move_to_head(cache, new_url); //����¼�Ƶ���ǰ��λ��

            if (debug_level > 0) {
                if (debug_level > 1)
                    printf("The record is in the cache\n");
                printf("<Domain Name: %s , IP: %s>\n\n", new_url, ip);
                out_cache_flag = 1;
            }
        }

        char sendbuf[MAX_BUF_LENGTH];
        memcpy(sendbuf, buf, len); //��ʼ�������ݰ�

        /*��Ӧ����header��ʽ
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
         // QRΪ1��ʾ��Ӧ��
         // OPCODEΪ0��ʾ��׼��ѯ(QUERY)
         // AA��Ȩ���𰸣�Ϊ0��ʾӦ����������Ǹ�������Ȩ������������
         // TCΪ0��ʾ����δ���ض�
         // RD�������ݹ飩Ϊ1��ʾϣ�����õݹ��ѯ
         // RA���ݹ���ã�Ϊ1��ʾ���ַ�����֧�ֵݹ��ѯ
         // ZΪ0����Ϊ�����ֶ�
         // RCODEΪ0����ʾû�в��
         //��˱���ͷ���ĵ�3-4�ֽ�Ϊֵ8180

        unsigned short num;

        if (strcmp(ip, "0.0.0.0") == 0) //�жϴ�ip�Ƿ�Ӧ�ñ�ǽ
        {
            num = htons(0x8183);
            memcpy(&sendbuf[2], &num, sizeof(unsigned short));
        }
        else {
            num = htons(0x8180);
            memcpy(&sendbuf[2], &num, sizeof(unsigned short));
        }

        if (strcmp(ip, "0.0.0.0") == 0) //�жϴ�ip�Ƿ�Ӧ�ñ�ǽ
        {

            num = htons(0x0); //���ûش���Ϊ0
        }
        else {
            num = htons(0x1); //�������ûش���Ϊ1
        }
        memcpy(&sendbuf[6], &num, sizeof(unsigned short));

        /*����DNS������Դ��¼��RR������
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

        // NAME�ֶΣ���Դ��¼�е�����ͨ���ǲ�ѯ���ⲿ�ֵ��������ظ�������ʹ��2�ֽڵ�ƫ��ָ���ʾ
        //���2λΪ11������ʶ��ָ�룬�����λΪ1100��12����ʾͷ������
        //��˸��ֶε�ֵΪ0xC00C
        unsigned short name = htons(0xc00c);
        memcpy(res_rec, &name, sizeof(unsigned short));
        pos += sizeof(unsigned short);

        // TYPE�ֶΣ���Դ��¼�����ͣ�1��ʾIPv4��ַ
        unsigned short type = htons(0x0001);
        memcpy(res_rec + pos, &type, sizeof(unsigned short));
        pos += sizeof(unsigned short);

        // CLASS�ֶΣ���ѯ�࣬ͨ��Ϊ1��IN��������Internet����
        unsigned short _class = htons(0x0001);
        memcpy(res_rec + pos, &_class, sizeof(unsigned short));
        pos += sizeof(unsigned short);

        // TTL�ֶΣ���Դ��¼����ʱ�䣨���޸ģ�
        unsigned long ttl = htonl(0x00000080);
        memcpy(res_rec + pos, &ttl, sizeof(unsigned long));
        pos += sizeof(unsigned long);

        // RDLENGTH�ֶΣ���Դ���ݳ��ȣ�������1��TYPE A��¼����Դ������4�ֽڵ�IP��ַ
        unsigned short RDlength = htons(0x0004);
        memcpy(res_rec + pos, &RDlength, sizeof(unsigned short));
        pos += sizeof(unsigned short);

        // RDATA�ֶΣ�������һ��IP��ַ
        unsigned long IP = (unsigned long)inet_addr(ip);
        memcpy(res_rec + pos, &IP, sizeof(unsigned long));
        pos += sizeof(unsigned long);
        pos += len;

        //�����ĺ���Ӧ���ֹ�ͬ���DNS��Ӧ���Ĵ���sendbuf
        memcpy(sendbuf + len, res_rec, sizeof(res_rec));

        len = sendto(my_socket, sendbuf, pos, 0, (SOCKADDR*)&client_addr,
            sizeof(client_addr));
        //������õı��Ķη����ͻ���

        if (len < 0 && debug_level > 1) {
            printf("Failed to send message to client\n");
        }

        char* p;
        p = sendbuf + len - 4;
        if (debug_level > 1) {
            printf("Send message: <Domain Name: %s ��IP: %u.%u.%u.%u>\n", new_url,
                (unsigned char)*p, (unsigned char)*(p + 1),
                (unsigned char)*(p + 2), (unsigned char)*(p + 3));
        }
        if (out_cache_flag && debug_level > 1) {
            outCache();
        }
    }
}