#ifndef _STR_H_
#define _STR_H_

#include"common.h"

void str_trim_crlf(char *str);//去掉回车和换行
void str_split(const char *str , char *left, char *right, char c);//以字符'c'分割字符串str
int str_all_space(const char *str);//去掉字符串中所有的空格
long long str_to_longlong(const char *str);//将字符串转换成long long 

#endif
