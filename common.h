#ifndef _COMMON_H_
#define _COMMON_H_

#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include<assert.h>

#include<fcntl.h>

#include<errno.h>

//socket
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>

//shdows password
#include<pwd.h>
#include<shadow.h>
#include<crypt.h>

//readdir
#include<sys/stat.h>
#include<dirent.h>

#include<time.h>

#include<signal.h>

#include<linux/capability.h>
//异常退出
#define ERR_EXIT(m)\
	do{\
	perror(m);\
	exit(EXIT_FAILURE);\
}while(0)
//用到的宏定义
#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND 32
#define MAX_ARG     1024

#define MAX_BUFFER_SIZE 1024


#endif /* _COMMON_H_ */
