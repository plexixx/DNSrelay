#include "dns.h"

int main(int argc, char* argv[])
{
    input(argc, argv);

    url_ip_table = create_list();    //��������ӳ���

    cache = create_list();          //����cacheӳ���

    readFile();

    initIDTable();

    WSAStartup(MAKEWORD(2, 2), &wsaData);  //���ݰ汾֪ͨ����ϵͳ������SOCKET�Ķ�̬���ӿ�

    initSocket();

    char buf[MAX_BUF_LENGTH];
    int len;

    while (TRUE)
    {
        memset(buf, '\0', MAX_BUF_LENGTH);
        //�ӿͻ��˽��ձ���
        //recvfrom()����������һ�����ݱ��������ݴ���buf�У�������Դ��ַ
        /*
            local_socket�������ӵı����׽ӿ�
            buf:�������ݻ�����
            sizeof(buf)�����ջ�������С
            0����־λflag����ʾ���ò�����ʽ��Ĭ����Ϊ0
            client:���񵽵����ݷ���Դ��ַ��Socket��ַ��
            sockaddr_in_size:��ַ����
            ����ֵ��recvLength���ɹ����յ������ݵ��ַ��������ȣ�������ʧ�ܷ���SOCKET_ERROR(-1)
        */

        SOCKADDR_IN tmp_sockaddr;
        len = -1;
        len = recvfrom(my_socket, buf, sizeof(buf), 0, (struct sockaddr*)&tmp_sockaddr, &length_client);/* Receive packet from client */


        if (len > 0)     //�յ�������
        {
            //if(tmp_sockaddr.sin_port == htons(53)&&memcmp(&(tmp_sockaddr),&(server_sockaddr),sizeof(SOCKADDR_IN))==0)
            if (tmp_sockaddr.sin_port == htons(53))      //�����ⲿ����������
            {
                receiveFromExtern(buf, len, tmp_sockaddr);
            }
            else        //���տͻ�������
            {
                receiveFromLocal(buf, len, tmp_sockaddr);
            }
        }
    }

    return 0;
}