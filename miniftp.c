#include"common.h"
#include"session.h"
#include"tunable.h"
#include"ftpcodes.h"
#include"hash.h"

void check_limits(session_t *sess);
unsigned int hash_func(unsigned int buckets, void *key);

unsigned int handle_ip_count(void *ip);
void handle_sigchld(int sig);
void drop_ip_count(void *ip);

static unsigned int client_counts;
static hash_t *s_ip_count_hash;
static hash_t *s_pid_ip_hash;
session_t *p_sess;

int main(int argc, char *argv[])
{
	parseconf_load_file("miniftpd.conf");

	/*
	printf("tunable_pasv_enable=%d\n", tunable_pasv_enable);
	printf("tunable_port_enable=%d\n", tunable_port_enable);
	printf("tunable_listen_port=%d\n", tunable_listen_port);
	printf("tunable_max_clients=%d\n", tunable_max_clients);
	printf("tunable_max_per_ip=%d\n", tunable_max_per_ip);
	printf("tunable_accept_timeout=%d\n", tunable_accept_timeout);
	printf("tunable_connect_timeout=%d\n", tunable_connect_timeout);
	printf("tunable_idle_session_timeout=%d\n", tunable_idle_session_timeout);
	printf("tunable_data_connection_timeout=%d\n", tunable_data_connection_timeout);
	//printf("tunable_loacl_umask=%d\n", tunable_loacl_umask);
	printf("tunable_upload_max_rate=%d\n", tunable_upload_max_rate);
	printf("tunable_download_mas_rate=%d\n", tunable_download_max_rate);
	if(tunable_listen_address != NULL)
		printf("tunable_listen_address=%s\n", tunable_listen_address);
	else
		printf("tunable_listen_address=NULL\n");

	if(getuid() != 0)
	{
		fprintf(stderr, "miniftpd: must be started as root\n");
		exit(EXIT_FAILURE);
	}
	*/

	daemon(0, 0);//使程序后台化运行
/*
typedef struct session
{
	//控制连接
	uid_t    uid;
	int ctrl_fd;
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

*/
	session_t sess =
	{
		//控制连接
		-1,-1, {0}, {0}, {0},
		//数据连接
		0,-1,-1,0,
		//协议状态
		0,0,0,
		//进程通道
		-1,-1,
		//限速
		0,0,0,0,
		//连接数限制
		0,0
	};

	p_sess = &sess;

	sess.bw_upload_rate_max = tunable_upload_max_rate;
	sess.bw_download_rate_max = tunable_download_max_rate;

	//1 socket();
	//2 bind();
	//3 listen();
	//得到一个监听的套接字
	int listenfd = tcp_server(tunable_listen_address, tunable_listen_port);
	int conn;
	struct sockaddr_in addrcli;
	socklen_t addrlen = sizeof(addrcli);
	pid_t pid;



	//每IP连接数
	s_ip_count_hash = hash_alloc(193, hash_func);
	s_pid_ip_hash   = hash_alloc(193, hash_func);

	signal(SIGCHLD, handle_sigchld);

	while(1)
	{
		//4 accept();
		if((conn = accept(listenfd, (struct sockaddr*)&addrcli, &addrlen)) < 0)
			ERR_EXIT("accept");

		client_counts++;
		sess.num_clients = client_counts;

		unsigned int ip = addrcli.sin_addr.s_addr;

		unsigned int per_ip_count = 0;
		unsigned int *p_count = NULL;

		sess.num_this_ip = handle_ip_count(&ip);
		//创建进程
		if((pid = fork()) < 0)
			ERR_EXIT("fork");
		if(pid == 0)
		{
			close(listenfd);//子进程关闭父进程的套接字
			sess.ctrl_fd = conn;
			check_limits(&sess);
			begin_session(&sess);//开启会话
		}
		else//父进程
		{
			//登记pid--IP表
			hash_add_entry(s_pid_ip_hash, &pid, sizeof(pid), &ip, sizeof(ip));
			close(conn);//父进程关闭子进程的套接字
		}
	}

	free(s_ip_count_hash);
	free(s_pid_ip_hash);
	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////
unsigned int hash_func(unsigned int buckets, void *key)
{
	return ((*(unsigned int*)key)  % buckets);
}

void check_limits(session_t *sess)
{
	if(sess->num_clients > tunable_max_clients)
	{
		//421 There are too many connected users, please try later.
		ftp_reply(sess, FTP_TOO_MANY_USERS, "There are too many connected users, please try later.");
		exit(EXIT_FAILURE);
	}

	if(sess->num_this_ip > tunable_max_per_ip)
	{
		//421 There are too many connections from your internet address.
		ftp_reply(sess, FTP_IP_LIMIT, "There are too many connections from your internet address.");
		exit(EXIT_FAILURE);
	}
}

unsigned int handle_ip_count(void *ip)
{
	unsigned int count;
	unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	if (p_count == NULL)//查找出来的p_count为空说明是新的IP，将其count置为1，插入hash表
	{
		count = 1;
		hash_add_entry(s_ip_count_hash, ip, sizeof(unsigned int),&count, sizeof(unsigned int));
	}
	else//否则给对应的count++
	{
		count = *p_count;
		++count;
		*p_count = count;
	}
	return count;
}

void handle_sigchld(int sig)
{
	pid_t pid;
	while((pid = waitpid(-1, NULL, WNOHANG)) > 0)//回收子进程
	{
		client_counts--;//总的最大连接数减一
		//通过pid查找IP
		unsigned int *ip = hash_lookup_entry(s_pid_ip_hash, &pid, sizeof(pid));
		if (ip == NULL)//???
		{
			continue;
		}
		//减少IP对应的count
		drop_ip_count(ip);
		//然后释放该pid--IP节点
		hash_free_entry(s_pid_ip_hash, &pid, sizeof(pid));
	}
}

void drop_ip_count(void *ip)
{
	unsigned int count;
	//通过IP查表得到对应count
	unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	if (p_count == NULL)
	{
		return;
	}
	//count--
	count = *p_count;
	--count;
	*p_count = count;
	//如果count减少到0，则释放IP--count节点
	if (count == 0)
	{
		hash_free_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	}
}
