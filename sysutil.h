#ifndef _SYSUTIL_H_
#define _SYSUTIL_H_

#include"common.h"
int tcp_server(const char *host, unsigned short port);

ssize_t readn(int fd, void *buf, size_t count);
ssize_t writen(int fd, const void *buf, size_t count);
ssize_t recv_peek(int sockfd, void *buf, size_t len);
ssize_t readline(int sockfd, void *buf, size_t maxline);

int getlocalip(char *ip);

const char* statbuf_get_perms(struct stat *sbuf);
const char* statbuf_get_date(struct stat *sbuf);

void send_fd(int sock_fd, int fd);
int recv_fd(const int sock_fd);

long get_time_sec(void);
long get_time_usec(void);
void nano_sleep(double seconds);

#endif /* _SYSUTIL_H_*/