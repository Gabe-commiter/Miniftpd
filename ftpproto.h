#ifndef _FTPPROTO_H_
#define _FTPPROTO_H_

#include"session.h"
#include"str.h"
#include"ftpcodes.h"
#include"sysutil.h"
#include"privsock.h"
#include"tunable.h"

void ftp_reply(session_t *sess, int status, const char *text);
void handle_child(session_t *sess);//处理子进程函数

#endif /* _FTPPROTO_H_ */
