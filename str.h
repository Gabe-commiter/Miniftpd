#ifndef _STR_H_
#define _STR_H_

#include"common.h"

void str_trim_crlf(char *str);//ȥ���س��ͻ���
void str_split(const char *str , char *left, char *right, char c);//���ַ�'c'�ָ��ַ���str
int str_all_space(const char *str);//ȥ���ַ��������еĿո�
long long str_to_longlong(const char *str);//���ַ���ת����long long 

#endif
