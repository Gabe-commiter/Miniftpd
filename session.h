#ifndef _SESSION_H_
#define _SESSION_H_

#include"common.h"
//#include"privsock.h"
//�Ự�ṹ��
typedef struct session
{
	//��������
	uid_t    uid;
	int ctrl_fd;//����������
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];

	//��������
	struct sockaddr_in *port_addr;
	int data_fd;
	int pasv_listen_fd;
	int data_process;

	//Э��״̬
	int is_ascii;
	char *rnfr_name;
	long long restart_pos;

	//����ͨ��
	int parent_fd; //nobody
	int child_fd;  //ftp

	//����
	unsigned int bw_upload_rate_max;
	unsigned int bw_download_rate_max;
	long bw_transfer_start_sec;
	long bw_transfer_start_usec;

	//����������
	unsigned int num_clients;
	unsigned int num_this_ip;
}session_t;

void begin_session(session_t *sess);


#endif /* _SESSION_H_ */
