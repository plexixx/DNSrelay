#ifndef __DNS_H__
#define __DNS_H__

#include "simlist.h"
#include <winsock2.h> 
#include <time.h> 

#pragma comment(lib,"Ws2_32.lib")
#pragma warning( disable : 4996)


#define DNS_HEAD_SIZE 12
#define DNS_PORT 53
#define ID_EXPIRE_TIME 1000
#define MAX_BUF_LENGTH 1024
#define MAX_CACHE_SIZE 8
#define MAX_IDLIST_LENGTH 32
#define MAX_LENGTH 60

#define BOOL int
#define TRUE 1
#define FALSE 0

/* ID转换器 */
typedef struct {
	unsigned short old_id;   /* 客户端发给DNS服务器的ID */
	SOCKADDR_IN client_addr; /* 请求者的客户端套接字 */
	int survival_time;       /* 超时的时间点 */
	BOOL finished;           /* 标记该请求是否已经完成 */
} IDtrans;
extern IDtrans IDtransformer[MAX_IDLIST_LENGTH]; /* ID转换表 */

extern int debug_level; /* 调试等级 */
extern char DNS_Server_IP[16]; /* 外部服务器 */


extern int ID_Count; /* 转换单元计数器 */

extern WSADATA wsaData;
extern SOCKET my_socket;

//extern struct sockaddr_in client_from, server_from;
extern struct sockaddr_in client, server;
extern int length_client;

extern nodeptr url_ip_table; /* 域名IP地址映射表 */
extern nodeptr cache;        /* 高速缓存 */


/* 控制台处理程序 */
void input(int argc, char* argv[]);

/* 根据配置文件读取域名-ip映射表 */
void readFile();

/* 初始化id转换表 */
void initIDTable();

/* 初始化套接字信息 */
void initSocket();

/* 更新cache内容 */
void addRecordToCache(char* url, char* ip);

/* 输出cache详细内容 */
void outCache();

/* 输出完整的数据包信息 */
void outPacket(char* buf, int len);

/* 分配新ID */
unsigned short addNewID(unsigned short ID, SOCKADDR_IN client_addr, BOOL finished);

/* DNS QName转换 */
void nameTranslate(char* buf, char* result);

/* 收到来自服务器的信息 */
void receiveFromExtern(char* buf, int len, SOCKADDR_IN server_addr);

/* 收到来自客户端的信息 */
void receiveFromLocal(char* buf, int len, SOCKADDR_IN server_addr);


#endif