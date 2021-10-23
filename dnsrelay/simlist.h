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


/* 创建空链表 */
nodeptr create_list();

/* 向链表头部添加结点 */
nodeptr push_front(nodeptr head, char* url, char* ip);

/* 删除链表的最后一个结点 */
nodeptr pop_back(nodeptr head);

/* 获取链表的长度 */
int size(nodeptr head);

/* 移动结点至链表的头部 */
nodeptr move_to_head(nodeptr head, char* url);

#endif
