#ifndef __SIMLIST_H__
#define __SIMLIST_H__


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma warning(disable : 4996)


typedef struct node {
    char url[100];
    char ip[21][50];
    int num;
    int round_num;
    struct node* next;
} Node, * nodeptr;


/* ���������� */
nodeptr create_list();

/* ������ͷ����ӽ�� */
nodeptr push_front(nodeptr head, char* url, char* ip);

/* ɾ����������һ����� */
nodeptr pop_back(nodeptr head);

/* ��ȡ����ĳ��� */
int size(nodeptr head);

/* �ƶ�����������ͷ�� */
nodeptr move_to_head(nodeptr head, char* url);

#endif
