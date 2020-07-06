#include"session.h"
//开启会话的函数
void begin_session(session_t *sess)
{

	priv_sock_init(sess);
   //在会话里面创建进程
	pid_t pid = fork();
	if(pid < 0)
		ERR_EXIT("begin_session:fork");
	if(pid == 0)
	{
		priv_sock_set_child_context(sess);
		//ftp 服务进程
		handle_child(sess);//子进程处理函数
	}
	else
	{
		priv_sock_set_parent_context(sess);
		//nobody 进程
		handle_parent(sess);//父进程处理函数
	}
}
