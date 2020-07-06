#include"session.h"
//�����Ự�ĺ���
void begin_session(session_t *sess)
{

	priv_sock_init(sess);
   //�ڻỰ���洴������
	pid_t pid = fork();
	if(pid < 0)
		ERR_EXIT("begin_session:fork");
	if(pid == 0)
	{
		priv_sock_set_child_context(sess);
		//ftp �������
		handle_child(sess);//�ӽ��̴�����
	}
	else
	{
		priv_sock_set_parent_context(sess);
		//nobody ����
		handle_parent(sess);//�����̴�����
	}
}
