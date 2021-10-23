#include "simlist.h"


/* ���������� */
nodeptr create_list() {
    nodeptr first = (nodeptr)malloc(sizeof(Node));
    if (first != NULL) {
        memset(first->url, '\0', sizeof(first->url));
        memset(first->ip, '\0', sizeof(first->ip));
        first->next = NULL;
        return first;
    }
    return NULL;
}

/* ������ͷ����ӽ�� */
nodeptr push_front(nodeptr head, char* url, char* ip) {
    nodeptr new_first = (nodeptr)malloc(sizeof(Node));
    new_first->num = 1;
    new_first->round_num = 0;
    memset(new_first->ip, '\0', sizeof(new_first->ip));
    if (new_first == NULL) {
        return NULL;
    }
    if (!(strcpy(new_first->url, url) && strcpy(new_first->ip[0], ip))) {
        // printf("����ʧ��\n");
        exit(1);
    }

    new_first->next = head;

    return new_first;
}

/* ��ӡ���� */
void print_list(nodeptr head) {
    int j = 0;
    while (head->next != NULL) {
        printf("NO.%d ����:%s -> IP��Ϣ:%s\n", j++, head->url, head->ip);
        head = head->next;
    }
}

/* ����url���������㣬���ض�Ӧ��ip��ַ */
char* get_ip(nodeptr head, char* url) {
    while (head->next != NULL) {
        if (strcmp(head->url, url) == 0) {
            head->round_num %= head->num;
            return head->ip[(head->round_num++) % head->num];
        }
        head = head->next;
    }

    char tmp[16] = "404_NOT_FOUND";
    return tmp;
}

/* ɾ����������һ����� */
nodeptr pop_back(nodeptr head) {
    if (head->next == NULL) {
        return head;
    }
    else {
        nodeptr prev = head, p = head;
        for (p = head; p->next->next != NULL; prev = p, p = p->next)
            ;

        if (p == head) {
            nodeptr temp = p->next;
            free(p);
            return temp;
        }
        else {
            prev->next = p->next;
            free(p);
            return head;
        }
    }
}

/* ��ȡ����ĳ��� */
int size(nodeptr head) {
    int cnt = 0;
    while (head->next) {
        cnt++;
        head = head->next;
    }
    return cnt;
}

/* �ƶ�����������ͷ�� */
nodeptr move_to_head(nodeptr head, char* url) {
    nodeptr prev = head, cur = head;
    while (cur->next != NULL) {
        if (strcmp(cur->url, url) == 0) {
            break;
        }
        prev = cur;
        cur = cur->next;
    }

    if (cur == head) {
        return head;
    }
    else {
        prev->next = cur->next;
        cur->next = head;
        return cur;
    }
}