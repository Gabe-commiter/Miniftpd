#include"ftpproto.h"

extern session_t *p_sess;

//空闲断开
void handle_alarm_timeout(int sig);
void start_cmdio_alarm(void);
void handle_sigalrm(int sig);
void start_data_alarm(void);

void limit_rate(session_t *sess, int bytes_transfered, int is_upload);

int get_transfer_fd(session_t *sess);
void list_common(session_t *sess);
//ftp的回复消息函数
void ftp_reply(session_t *sess, int status, const char *text)
{
	char buf[MAX_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "%d %s\r\n",status, text);//将status和text格式化到buf中
	writen(sess->ctrl_fd,  buf, strlen(buf));//发送消息
}

static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
//static void do_stru(session_t *sess);
//static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);
//实现命令映射的结构体
typedef struct ftpcmd
{
	const char *cmd;
	void (*cmd_handler)(session_t *sess);
} ftpcmd_t;
//实现命令映射的结构体数组
static ftpcmd_t ctrl_cmds[] =
{
	{"USER", do_user},
	{"PASS", do_pass},
	{"SYST", do_syst},
	{"FEAT", do_feat},
	{"PWD",  do_pwd },
	{"TYPE", do_type},
	{"PORT", do_port},
	{"PASV", do_pasv},
	{"LIST", do_list},
	{"CWD" , do_cwd },
	{"MKD" , do_mkd },
	{"RMD" , do_rmd },
	{"DELE", do_dele},
	{"SIZE", do_size},
	{"RNFR", do_rnfr},
	{"RNTO", do_rnto},
	{"RETR", do_retr},
	{"STOR", do_stor},
	{"REST", do_rest},
	{"QUIT", do_quit},
	{"NOOP", do_noop}
};


//////////////////////////////////////////////////////////////////////////////
//空闲断开

/*
void handle_alarm_timeout(int sig)
{
	shutdown(p_sess->ctrl_fd, SHUT_RD);
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout.");
	shutdown(p_sess->ctrl_fd, SHUT_WR);
	exit(EXIT_SUCCESS);
}
*/
void handle_alarm_timeout(int sig)
{
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout.");
	close(p_sess->ctrl_fd);
	exit(EXIT_SUCCESS);
}

void start_cmdio_alarm(void)
{
	if(tunable_idle_session_timeout != 0)
	{
		signal(SIGALRM, handle_alarm_timeout); //安装闹钟信号
		alarm(tunable_idle_session_timeout);
	}
}

void handle_sigalrm(int sig)
{
	if (!p_sess->data_process)
	{
		ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data timeout. Reconnect. Sorry.");
		exit(EXIT_FAILURE);
	}

	// 否则，当前处于数据传输的状态收到了超时信号
	p_sess->data_process = 0;
	start_data_alarm();
}

void start_data_alarm(void)
{
	if(tunable_data_connection_timeout != 0)
	{
		signal(SIGALRM, handle_sigalrm);
		alarm(tunable_data_connection_timeout);
	}
	else if(tunable_idle_session_timeout != 0)
	{
		alarm(0);
	}
}

///////////////////////////////////////////////////////////////////////////////
void handle_child(session_t *sess)
{
	ftp_reply(sess, FTP_GREET, "(miniftpd 1.0)");
	int ret;
	while(1)
	{
		//每次进入循环，清零
		memset(sess->cmdline, 0, sizeof(sess->cmdline));
		memset(sess->cmd, 0, sizeof(sess->cmd));
		memset(sess->arg, 0, sizeof(sess->arg));

		start_cmdio_alarm();

		//ssize_t readline(int sockfd, void *buf, size_t maxline);
		ret = readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
		if(ret == 0)
		{
			exit(EXIT_SUCCESS);
		}
		else if(ret < 0)
		{
			ERR_EXIT("readline");
		}
		str_trim_crlf(sess->cmdline);
		//printf("cmdline = [%s]\n", sess->cmdline);
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
		//printf("command = [%s]\n", sess->cmd);
		//printf("arg = [%s]\n", sess->arg);

		size_t n = sizeof(ctrl_cmds) / sizeof(ftpcmd_t);
		size_t i;
		for(i=0; i<n; ++i)
		{
			if(strcmp(ctrl_cmds[i].cmd, sess->cmd) == 0)//有命令
			{
				if(ctrl_cmds[i].cmd_handler != NULL)//实现的
				{
					(*ctrl_cmds[i].cmd_handler)(sess);//*解引用取得函数，再传参
				}
				else//未实现的
				{
					char buf[1024] = {0};
					sprintf(buf, "%s not implemented.", sess->cmd);//格式化字符串，把命令放回去
					ftp_reply(sess, FTP_COMMANDNOTIMPL, buf);//回复客户端命令未实现
				}
				break;
			}
		}
		if(i >= n)//没有这条命令(找不到)
			ftp_reply(sess, FTP_BADCMD, "Unknown command.");
	}
}

///////////////////////////////////////////////////////////////////////////////
//鉴权登录 系统特性命令实现
static void do_user(session_t *sess)
{
	struct passwd *pw = getpwnam(sess->arg);
	if(pw != NULL)
		sess->uid = pw->pw_uid;//保存用户uid

	//331 Please specify the password.
	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");
}

static void do_pass(session_t *sess)
{
	struct passwd *pw = getpwuid(sess->uid);//根据用户uid，来获取密码
	if(pw == NULL)//用户是不存在的
	{
		//530 Login incorrect.
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	struct spwd *spw = getspnam(pw->pw_name);//根据密码名字获取影子文件

	char *crypt_passwd = crypt(sess->arg, spw->sp_pwdp);
	if(strcmp(spw->sp_pwdp, crypt_passwd) != 0)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}
	//变更群id、用户id、当前的用户目录
	setegid(pw->pw_gid);
	seteuid(pw->pw_uid);
	chdir(pw->pw_dir);

	//230 Login successful.
	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}
//系统信息
static void do_syst(session_t *sess)
{
	// 215 UNIX Type: L8
	ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
}

static void do_feat(session_t *sess)
{
	 //ftp_reply(sess, FTP_FEAT, "-Features:");
	 writen(sess->ctrl_fd, "211-Features:\r\n", strlen("211-Features:\r\n"));
	 writen(sess->ctrl_fd, "EPRT\r\n", strlen("EPRT\r\n"));
	 writen(sess->ctrl_fd, "EPSV\r\n", strlen("EPSV\r\n"));
	 writen(sess->ctrl_fd, "MDTM\r\n", strlen("MDTM\r\n"));
	 writen(sess->ctrl_fd, "PASV\r\n", strlen("PASV\r\n"));
	 writen(sess->ctrl_fd, "REST STREAM\r\n", strlen("REST STREAM\r\n"));
	 writen(sess->ctrl_fd, "SIZE\r\n", strlen("SIZE\r\n"));
	 writen(sess->ctrl_fd, "TVFS\r\n", strlen("TVFS\r\n"));
	 writen(sess->ctrl_fd, "UTF8\r\n", strlen("UTF8\r\n"));
	 ftp_reply(sess, FTP_FEAT, "end");
}

static void do_pwd(session_t *sess)
{
	char text[1024] = {0};
	char dir[1024+1] = {0};
	getcwd(dir, 1024);
	sprintf(text, "\"%s\"", dir);
	ftp_reply(sess, FTP_PWDOK, text);
}

static void do_type(session_t *sess)
{
	//A
	// 200 Switching to ASCII mode.
	if(strcmp(sess->arg, "A") == 0)
	{
		sess->is_ascii = 1;
		ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
	}
	//I
	//200 Switching to Binary mode.
	else if(strcmp(sess->arg, "I") == 0)
	{
		sess->is_ascii = 0;
		ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
	}
	//500 Unrecognised TYPE command.
	else
	{
		ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
	}
}

static void do_port(session_t *sess)
{
	unsigned char v[6] = {0};
	sscanf(sess->arg, "%d, %d, %d, %d, %d, %d,", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);//从字符串输入数组v
	//printf("v[0] = %d, v[1]=%d, v[2]=%d, v[3]=%d, v[4]=%d, v[5]=%d\n",
	//	v[0],v[1],v[2],v[3],v[4],v[5]);
	sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));//session结构体存的是一个指针，在这里开辟空间
	memset(sess->port_addr, 0, sizeof(struct sockaddr_in));
	//sin_family
	sess->port_addr->sin_family = AF_INET;
	//sin_addr
	unsigned char *p = (unsigned char*)&sess->port_addr->sin_addr;//找到该部分内容存储开始的位置，填充内容
	p[0] = v[0];
	p[1] = v[1];
	p[2] = v[2];
	p[3] = v[3];
	//sin_port
	p = (unsigned char*)&sess->port_addr->sin_port;
	p[0] = v[4];
	p[1] = v[5];

	//printf("ip = %s\n", inet_ntoa(sess->port_addr->sin_addr));
	//printf("port = %d\n", ntohs(sess->port_addr->sin_port));网络字节序转为本地字节序

	//200 PORT command successful. Consider using PASV.
	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
}

/*
static void do_pasv(session_t *sess)
{
	//ip = "192.168.0.200"
	char *ip = "192.168.0.200";
	int sockfd = tcp_server(ip, 0);

	struct sockaddr_in address;
	socklen_t addrlen = sizeof(address);
	if(getsockname(sockfd, (struct sockaddr*)&address, &addrlen) < 0)
		ERR_EXIT("getsockname");

	//printf("ip = %s\n", inet_ntoa(addr.sin_addr));
	//printf("port = %d\n",ntohs(addr.sin_port));
	unsigned short port = ntohs(address.sin_port);
	unsigned char addr[6] = {0};
	sscanf(ip, "%u.%u.%u.%u", &addr[0], &addr[1], &addr[2], &addr[3]);
	addr[4] = ((port>>8) & 0x00ff);
	addr[5] = port & 0x00ff;

	char buf[MAX_BUFFER_SIZE] = {0};
	sprintf(buf, "Entering Passive Mode (%u,%u,%u,%u,%u,%u)", addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
	//port = 8080
	//227 Entering Passive Mode (192,168,0,200,76,240).
	sess->pasv_listen_fd = sockfd;
	ftp_reply(sess, FTP_PASVOK, buf);
}
*/

static void do_pasv(session_t *sess)
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);

	//char ip[] = "192.168.0.200";
	char ip[16];
	getlocalip(ip);
	unsigned short port = (unsigned short)priv_sock_get_int(sess->child_fd);
	unsigned char addr[6] = {0};

	sscanf(ip, "%u.%u.%u.%u", &addr[0], &addr[1], &addr[2], &addr[3]);

	addr[4] = port>>8;
	addr[5] = port & 0x00ff;

	char buf[MAX_BUFFER_SIZE] = {0};
	sprintf(buf, "Entering Passive Mode (%u,%u,%u,%u,%u,%u)", addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
	ftp_reply(sess, FTP_PASVOK, buf);
}

///////////////////////////////////////////////////////
//数据连接

int port_active(session_t *sess)
{
	if(sess->port_addr != 0)//不为空的话就是主动连接（因为主动模式需要解析客户端发来的IP和PORT）
		return 1;
	return 0;
}
int pasv_active(session_t *sess)
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
	return priv_sock_get_int(sess->child_fd);
}
//获取数据连接
int get_transfer_fd(session_t *sess)
{
	if(!port_active(sess) && !pasv_active(sess))
	{
		//425 Use PORT or PASV first(两个方式都没有被激活)
		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first");
		return 0;
	}


	if(port_active(sess) && pasv_active(sess))
	{
		//425 PORT both PASV active.
		ftp_reply(sess, FTP_BADSENDCONN, "PORT both PASV active.");
		return 0;
	}

	if(port_active(sess))
	{
		priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);

		char *ip = inet_ntoa(sess->port_addr->sin_addr);
		priv_sock_send_buf(sess->child_fd, ip, strlen(ip));
		priv_sock_send_int(sess->child_fd, ntohs(sess->port_addr->sin_port));

		if(sess->port_addr)
		{
			free(sess->port_addr);
			sess->port_addr = 0;
		}

		char res = priv_sock_get_result(sess->child_fd);
		if(res == PRIV_SOCK_RESULT_OK)
		{
			sess->data_fd = priv_sock_recv_fd(sess->child_fd);
			return 1;
		}
		else
			return 0;
	}

	if(pasv_active(sess))
	{
		priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
		char ret = priv_sock_get_result(sess->child_fd);
		if(ret == PRIV_SOCK_RESULT_BAD)
			return 0;
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}


	//数据连接_空闲断开
	start_data_alarm();

	return 1;
}

void list_common(session_t *sess)
{
	DIR *dir = opendir(".");
	if (dir == NULL)
	{
		return;
	}

	struct dirent *dt;
	struct stat sbuf;
	while ((dt = readdir(dir)) != NULL)
	{
		if (lstat(dt->d_name, &sbuf) < 0)
		{
			continue;
		}
        if (dt->d_name[0] == '.')
		{
			continue;
        }

		char buf[1024] = {0};

		const char *perms = statbuf_get_perms(&sbuf);

		int off = 0;
		off += sprintf(buf, "%s ", perms);
		off += sprintf(buf + off, " %3d %-8d %-8d ", (int)sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
		off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);

		const char *datebuf = statbuf_get_date(&sbuf);
		off += sprintf(buf + off, "%s ", datebuf);
		if (S_ISLNK(sbuf.st_mode))
		{
			char tmp[1024] = {0};
			readlink(dt->d_name, tmp, sizeof(tmp));
			off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);
		}
		else
		{
			off += sprintf(buf + off, "%s\r\n", dt->d_name);
		}

		writen(sess->data_fd, buf, strlen(buf));
	}

	closedir(dir);
}
//实现LIST命令
static void do_list(session_t *sess)
{
	//1  建立数据连接  port  pasv
	if(get_transfer_fd(sess) == 0)
		return;
	//printf("data_fd = %d\n", sess->data_fd);
	//2  150 Here comes the directory listing.
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	//3  list_common
	list_common(sess);

	close(sess->data_fd);
	sess->data_fd = -1;

	//4  226 Directory send OK.
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}

/////////////////////////////////////////////////////////////////////////////////////////////
//cwd、cdup、mkd、dele、rmd、size、rnfr、rnto

static void do_cwd(session_t *sess)
{
	if (chdir(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Failed to change directory.");
		return;
	}

	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

static void do_cdup(session_t *sess)
{
	if (chdir("..") < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Failed to change directory.");
		return;
	}

	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

/*
static void do_mkd(session_t *sess)
{
	if(mkdir(sess->arg, 0755) < 0)
	{
		 //550 Permission denied.
		 ftp_reply(sess, FTP_NOPERM, "Permission denied.");
		 return;
	}
	// 257 "/home/51cc/C12/Project/Test1" created
	char buf[MAX_BUFFER_SIZE] = {0};
	if(getcwd(buf, MAX_BUFFER_SIZE) == NULL)
	{
		//
	}
	else
	{
		//printf("buf = %s\n",buf);
		sprintf(buf, "\"%s\%s\" created",buf,sess->arg);
		ftp_reply(sess, FTP_MKDIROK, buf);
	}
}
*/

static void do_mkd(session_t *sess)
{
	if(mkdir(sess->arg, 0755) < 0)
	{
		if(errno == EEXIST)
		{
			// 550 Create directory operation failed.
			ftp_reply(sess, FTP_FILEFAIL, "Create directory operation failed.");
		}
		else
		{
			//550 Permission denied.
			ftp_reply(sess, FTP_NOPERM, "Permission denied.");
		}
		return;
	}
	// 257 "/home/51cc/C12/Project/Test1" created
	char buf[MAX_BUFFER_SIZE] = {0};
	if(getcwd(buf, MAX_BUFFER_SIZE) == NULL)
	{
		//ftp_rely();
	}
	else
	{
		//printf("buf = %s\n",buf);
		sprintf(buf, "\"%s\%s\" created",buf,sess->arg);
		ftp_reply(sess, FTP_MKDIROK, buf);
	}
}

static void do_rmd(session_t *sess)
{
	if(rmdir(sess->arg) < 0)
	{
		//550 Remove directory operation failed.
		ftp_reply(sess, FTP_NOPERM, "Remove directory operation failed.");
		return;
	}
	//250 Remove directory operation successful.
	ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successful.");
}

static void do_dele(session_t *sess)
{
	if(unlink(sess->arg) < 0)
	{
		//550 Delete operation failed.
		ftp_reply(sess, FTP_NOPERM, "Delete operation failed.");
		return;
	}

	// 250 Delete operation successful.
	ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");

}

static void do_size(session_t *sess)
{
	struct stat sbuf;
	if(stat(sess->arg, &sbuf) < 0)
	{
		// 550 Could not get file size.
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}

	// 213 6
	char buf[MAX_BUFFER_SIZE] = {0};
	sprintf(buf, "%d", sbuf.st_size);
	ftp_reply(sess, FTP_STATFILE_OK, buf);
}

static void do_rnfr(session_t *sess)
{
	sess->rnfr_name = (char*)malloc(strlen(sess->arg)+1);
	assert(sess->rnfr_name != NULL);

	strcpy(sess->rnfr_name, sess->arg);
	//350 Ready for RNTO.
	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}
static void do_rnto(session_t *sess)
{
	if(sess->rnfr_name == 0)
	{
		 //503 RNFR required first.
		 ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
		 return;
	}
	int ret = rename(sess->rnfr_name, sess->arg);

	free(sess->rnfr_name);
	sess->rnfr_name = 0;

	if(ret < 0)
	{
		// 550 Rename failed.
		ftp_reply(sess, FTP_FILEFAIL, "Rename failed.");
		return;
	}
	//250 Rename successful.
	ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");
}

/////////////////////////////////////////////////////////////////////////////
//下载 上传 续载 限速

void limit_rate(session_t *sess, int bytes_transfered, int is_upload)
{
	//数据连接_空闲断开
	sess->data_process = 1;

	if(sess->bw_upload_rate_max==0 && sess->bw_download_rate_max==0)
		return;

	long curr_sec = get_time_sec();
	long curr_usec = get_time_usec();

	double elapsed;
	elapsed = (double)(curr_sec - sess->bw_transfer_start_sec);
	elapsed += (double)(curr_usec - sess->bw_transfer_start_usec) / (double)1000000;

	unsigned int bw_rate = (unsigned int)((double)bytes_transfered / elapsed);
	double rate_ratio;

	if(is_upload)
	{
		if(bw_rate <= sess->bw_upload_rate_max)
		{
			sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = curr_usec;
			return;
		}
		rate_ratio = (bw_rate / sess->bw_upload_rate_max);
	}
	else
	{
		if(bw_rate <= sess->bw_download_rate_max)
		{
			sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = curr_usec;
			return;
		}
		rate_ratio = (bw_rate / sess->bw_download_rate_max);
	}

	double pause_time = (rate_ratio - (double)1) * elapsed;
	nano_sleep(pause_time);
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();
}

static void do_retr(session_t *sess)
{
	//1建立数据连接
	if(get_transfer_fd(sess) == 0)
		return;

	struct stat sbuf;
	stat(sess->arg, &sbuf);

	char buf[MAX_BUFFER_SIZE] = {0};
	//2判断传输模式
	if(sess->is_ascii)
		sprintf(buf,  "Opening ASCII mode data connection for %s (%ld bytes)",
			sess->arg, sbuf.st_size);//Ascii
	else
		sprintf(buf, "Opening BINARY mode data connection for %s (%ld bytes)",
			sess->arg, sbuf.st_size);

	//3回复150
	ftp_reply(sess, FTP_DATACONN, buf);

	//4传输数据
	int fd = open(sess->arg, O_RDONLY);
	if(fd < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	long long file_total_size = sbuf.st_size;
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;

	if(offset >= file_total_size)
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
		return;
	}

	unsigned long left_bytes = file_total_size - offset;

	lseek(fd, offset, SEEK_SET);

	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();



	int count = 0;
	int flag = 0, ret = 0;
	while(left_bytes > 0)
	{
		memset(buf, 0, sizeof(buf));
		count = read(fd, buf, MAX_BUFFER_SIZE);
		if(count < 0)
		{
			flag = 1;
		}

		limit_rate(sess, count, 0);

		ret = write(sess->data_fd, buf, count);
		if(ret < 0)
		{
			flag = 2;
		}
		else if(ret != count)
		{
			flag = 3;
		}
		left_bytes -= count;
	}

	close(fd);
	close(sess->data_fd);
	sess->data_fd = -1;
	//5回复226
	if(flag == 0)
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	else if(flag == 1)
		ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
	else if(flag == 2)
		ftp_reply(sess, FTP_BADSENDFILE, "Failure writing from net file.");
	else if(flag == 3)
		ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
}

static void do_stor(session_t *sess)
{

	//1建立数据连接
	if(get_transfer_fd(sess) == 0)
		return;

	//150 Ok to send data.
	ftp_reply(sess, FTP_DATACONN, "Ok to send data.");

	//4传输数据
	int fd = open(sess->arg, O_CREAT|O_WRONLY, 0755);
	if(fd < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}


	unsigned long offset = sess->restart_pos;
	sess->restart_pos = 0;
	lseek(fd, offset, SEEK_SET);

	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

	char buf[MAX_BUFFER_SIZE];
	int count = 0;
	int flag = 0, ret = 0;
	while(1)
	{
		memset(buf, 0, sizeof(buf));
		count = read(sess->data_fd, buf, MAX_BUFFER_SIZE);
		if(count == 0)
		{
			break;
		}
		else if(count < 0)
		{
			flag = 1;
			break;
		}

		limit_rate(sess, count, 1);

		ret = write(fd, buf, count);
		if(ret < 0)
		{
			flag = 2;
			break;
		}
		else if(ret != count)
		{
			flag = 3;
			break;
		}
	}

	close(fd);
	close(sess->data_fd);
	sess->data_fd = -1;
	//5回复226
	if(flag == 0)
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	else if(flag == 1)
		ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
	else if(flag == 2)
		ftp_reply(sess, FTP_BADSENDFILE, "Failure writing from net file.");
	else if(flag == 3)
		ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
}

static void do_rest(session_t *sess)
{
	sess->restart_pos = str_to_longlong(sess->arg);
	char buf[MAX_BUFFER_SIZE] = {0};
	sprintf(buf, "Restart position accepted (%u).", sess->restart_pos);
	// 350 Restart position accepted (4161536).
	ftp_reply(sess, FTP_RESTOK, buf);
}

static void do_quit(session_t *sess)
{
	ftp_reply(sess, FTP_GOODBYE, "Goodbye.");
	exit(EXIT_SUCCESS);
}

static void do_noop(session_t *sess)
{
	ftp_reply(sess, FTP_NOOPOK, "NOOP ok.");
}
