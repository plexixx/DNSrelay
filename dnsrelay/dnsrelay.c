#include "dns.h"

int main(int argc, char* argv[])
{
    input(argc, argv);

    url_ip_table = create_list();    //创建本地映射表

    cache = create_list();          //创建cache映射表

    readFile();

    initIDTable();

    WSAStartup(MAKEWORD(2, 2), &wsaData);  //根据版本通知操作系统，启用SOCKET的动态链接库

    initSocket();

    char buf[MAX_BUF_LENGTH];
    int len;

    while (TRUE)
    {
        memset(buf, '\0', MAX_BUF_LENGTH);
        //从客户端接收报文
        //recvfrom()函数：接收一个数据报，将数据存至buf中，并保存源地址
        /*
            local_socket：已连接的本地套接口
            buf:接收数据缓冲区
            sizeof(buf)：接收缓冲区大小
            0：标志位flag，表示调用操作方式，默认设为0
            client:捕获到的数据发送源地址（Socket地址）
            sockaddr_in_size:地址长度
            返回值：recvLength：成功接收到的数据的字符数（长度），接收失败返回SOCKET_ERROR(-1)
        */

        SOCKADDR_IN tmp_sockaddr;
        len = -1;
        len = recvfrom(my_socket, buf, sizeof(buf), 0, (struct sockaddr*)&tmp_sockaddr, &length_client);/* Receive packet from client */


        if (len > 0)     //收到了数据
        {
            //if(tmp_sockaddr.sin_port == htons(53)&&memcmp(&(tmp_sockaddr),&(server_sockaddr),sizeof(SOCKADDR_IN))==0)
            if (tmp_sockaddr.sin_port == htons(53))      //接收外部服务器数据
            {
                receiveFromExtern(buf, len, tmp_sockaddr);
            }
            else        //接收客户端数据
            {
                receiveFromLocal(buf, len, tmp_sockaddr);
            }
        }
    }

    return 0;
}