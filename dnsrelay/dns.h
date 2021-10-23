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

/* IDת���� */
typedef struct {
	unsigned short old_id;   /* �ͻ��˷���DNS��������ID */
	SOCKADDR_IN client_addr; /* �����ߵĿͻ����׽��� */
	int survival_time;       /* ��ʱ��ʱ��� */
	BOOL finished;           /* ��Ǹ������Ƿ��Ѿ���� */
} IDtrans;
extern IDtrans IDtransformer[MAX_IDLIST_LENGTH]; /* IDת���� */

extern int debug_level; /* ���Եȼ� */
extern char DNS_Server_IP[16]; /* �ⲿ������ */


extern int ID_Count; /* ת����Ԫ������ */

extern WSADATA wsaData;
extern SOCKET my_socket;

//extern struct sockaddr_in client_from, server_from;
extern struct sockaddr_in client, server;
extern int length_client;

extern nodeptr url_ip_table; /* ����IP��ַӳ��� */
extern nodeptr cache;        /* ���ٻ��� */


/* ����̨������� */
void input(int argc, char* argv[]);

/* ���������ļ���ȡ����-ipӳ��� */
void readFile();

/* ��ʼ��idת���� */
void initIDTable();

/* ��ʼ���׽�����Ϣ */
void initSocket();

/* ����cache���� */
void addRecordToCache(char* url, char* ip);

/* ���cache��ϸ���� */
void outCache();

/* ������������ݰ���Ϣ */
void outPacket(char* buf, int len);

/* ������ID */
unsigned short addNewID(unsigned short ID, SOCKADDR_IN client_addr, BOOL finished);

/* DNS QNameת�� */
void nameTranslate(char* buf, char* result);

/* �յ����Է���������Ϣ */
void receiveFromExtern(char* buf, int len, SOCKADDR_IN server_addr);

/* �յ����Կͻ��˵���Ϣ */
void receiveFromLocal(char* buf, int len, SOCKADDR_IN server_addr);


#endif