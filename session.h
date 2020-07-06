#ifndef _SESSION_H_
#define _SESSION_H_

#include"common.h"
//#include"privsock.h"
//会话结构体
typedef struct session
{
	//控制连接
	uid_t    uid;
	int ctrl_fd;//控制描述符
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];

	//数据连接
	struct sockaddr_in *port_addr;
	int data_fd;
	int pasv_listen_fd;
	int data_process;

	//协议状态
	int is_ascii;
	char *rnfr_name;
	long long restart_pos;

	//进程通道
	int parent_fd; //nobody
	int child_fd;  //ftp

	//限速
	unsigned int bw_upload_rate_max;
	unsigned int bw_download_rate_max;
	long bw_transfer_start_sec;
	long bw_transfer_start_usec;

	//连接数限制
	unsigned int num_clients;
	unsigned int num_this_ip;
}session_t;

void begin_session(session_t *sess);


#endif /* _SESSION_H_ */
