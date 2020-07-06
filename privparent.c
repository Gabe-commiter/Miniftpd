#include"privparent.h"

static void privop_port_get_data_sock(session_t *sess);
static void privop_pasv_active(session_t *sess);
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);

/*
int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	return syscall(__NR_capset, hdrp, datap);
}
*/

void minimize_privilege(void)
{
	struct passwd *pw = getpwnam("nobody");
	if(pw == NULL)
		return;
	if(setegid(pw->pw_gid) < 0)
		ERR_EXIT("setegid");
	if(seteuid(pw->pw_uid) < 0)
		ERR_EXIT("seteuid");

	struct __user_cap_header_struct cap_header;
	struct __user_cap_data_struct   cap_data;

	memset(&cap_header, 0, sizeof(cap_header));
	memset(&cap_data,   0, sizeof(cap_data));

	cap_header.version = _LINUX_CAPABILITY_VERSION_1;
	cap_header.pid = 0;

	__u32 cap_mask = 0;
	cap_mask |= (1<<CAP_NET_BIND_SERVICE);
	cap_data.effective = cap_data.permitted = cap_mask;
	cap_data.inheritable = 0;

	capset(&cap_header, &cap_data);
}

void handle_parent(session_t *sess)
{
	minimize_privilege();

	char cmd;
	while(1)
	{
		cmd = priv_sock_get_cmd(sess->parent_fd);
		switch(cmd)
		{
			case PRIV_SOCK_GET_DATA_SOCK:
				privop_port_get_data_sock(sess);
				break;
			case PRIV_SOCK_PASV_ACTIVE:
				privop_pasv_active(sess);
				break;
			case PRIV_SOCK_PASV_LISTEN:
				privop_pasv_listen(sess);
				break;
			case PRIV_SOCK_PASV_ACCEPT:
				privop_pasv_accept(sess);
				break;
		}
	}
}

static void privop_port_get_data_sock(session_t *sess)
{
	int datafd;
	if((datafd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
		
	socklen_t addrlen = sizeof(struct sockaddr);
		
	int on = 1;
	if(setsockopt(datafd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0)
		ERR_EXIT("setsockopt");
	//20¶Ë¿ÚµÄ°ó¶¨
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_port = htons(20);
	address.sin_addr.s_addr = inet_addr("192.168.0.200");

	if(bind(datafd, (struct sockaddr*)&address, addrlen) < 0)
		ERR_EXIT("bind 20");
		

	struct sockaddr_in port_addr;
	char ip[16] = {0};
	unsigned short port;

	priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));
	port = priv_sock_get_int(sess->parent_fd);
	port_addr.sin_family = AF_INET;
	port_addr.sin_port = htons(port);
	port_addr.sin_addr.s_addr = inet_addr(ip);

	if(connect(datafd, (struct sockaddr*)&port_addr, addrlen) < 0)
	{
		close(datafd);
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}

	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, datafd);
	close(datafd);
}

static void privop_pasv_active(session_t *sess)
{
	if(sess->pasv_listen_fd != -1)
		priv_sock_send_int(sess->parent_fd, 1);
	else
		priv_sock_send_int(sess->parent_fd, 0);
}
static void privop_pasv_listen(session_t *sess)
{
	//char *ip = "192.168.0.200";
	char ip[16];
	getlocalip(ip);
	int sockfd = tcp_server(ip, 0);
	struct sockaddr_in address;
	socklen_t addrlen = sizeof(address);
	if(getsockname(sockfd, (struct sockaddr*)&address, &addrlen) < 0)
		ERR_EXIT("getsockname");

	sess->pasv_listen_fd = sockfd;
	unsigned short port = ntohs(address.sin_port);
	priv_sock_send_int(sess->parent_fd, (int)port);
}

static void privop_pasv_accept(session_t *sess)
{
	int datafd;
	struct sockaddr_in addrcli;
	socklen_t addrlen = sizeof(addrcli);
	if((datafd = accept(sess->pasv_listen_fd, (struct sockaddr*)&addrcli, &addrlen))<0)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, datafd);

	close(sess->pasv_listen_fd);
	close(datafd);
}