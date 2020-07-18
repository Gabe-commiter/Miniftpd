# 项目概述
本项目是Linux下vsftp服务器的简化版，实现了vsftp的部分功能。实现了FTP的两种工作模式：被动模式和主动模式。这里的主动模式和被动模式都是站在服务器的角度上来说的。主动模式：cli要把自己的IP+PORT告诉ser,ser主动去连接cli。被动模式：ser告知cli自己的IP+PORT，等待cli来连接自己。

## 为什么一定要分主动模式和被动模式呢？

客户端处于NAT网络之后--主动模式，服务器只能得知NAT的地址而不知道客户端的IP地址，因此FTP服务器会以20端口主动向NAT的PORTBB发送主动连接，但NAT并没有开启BB端口，因而连接被拒绝。所以这时候就需要被动模式，被动模式的控制连接和数据连接都是由客户端发起的，这样就不会出现服务器到客户端的数据端口的入方向连接被防火墙拦截的问题。

## 项目的整体架构梳理如下：
采用多进程模型来实现同时为多个客户端服务的功能。启动服务器程序之后，运行一个主进程。每当有一个客户端到达的时候主进程就会派生出一个子进程来为客户端服务。随后子进程会开启一个会话，再次fork派生出一个子进程。其中nobody进程用来协助ftp进程建立主动/被动模式的数据连接，ftp进程负责处理客户端请求的FTP服务。通过capabilities提升权限，使得nobody进程可以操作20端口（众所周知端口）。此外通过socketpair来作为nobody进程和ftp进程之间的通信手段，项目中专门设计了一个privsocket模块用来实现此功能。

## 项目中的一些技术点：

- 鉴权登录  
主要是do_user和do_pass两个命令的实现，将用户验证和密码验证分离设计，以保证良好的用户体验。  

  - do_user的实现，调用getpwnam函数，将登陆的用户名的passwd取出来，如果不为空的话，将pw_uid注册进session会话结构体中的uid中。在项目中，把uid作为一个用户的唯一标识。完成用户验证之后，就可以进行密码的验证了。
  - do_pass的实现，调用getpwuid函数，得到已经验证过的账户的passwd;然后通过getspnam函数，得到影子密码结构体 spwd,取spwd->sp_pwdp作为密钥，调用crypt函数加密(DES),加密后的返回值和密钥比较，如果相同验证通过。
  - getuid函数可以来判断启动进程的用户是不是root用户。  


- 列表显示  
客户端的列表显示是以图形化的界面来展示的，但实际上服务器发送过来的是一个文本文件供客户端解析。那么如何获取用户的的目录呢？Linux下描述文件信息的结构体stat和描述目录的结构体dirent。细节的话：涉及到如何获取文件创建的时间，结构体 tm，lstat函数（获取链接文件的信息，不穿透），stat中的st_mode可以用来判断文件的权限。

- 上传和下载功能实现  
上传和下载其实就是,从某一端的某个文件一直读，然后写到sockfd中去，另一端接收。用left_bytes表示剩下还没有读的字节数，用lseek()函数和offset变量来表示当前已经读取的位置。里面的读写用到的系统调用read()函数和write()函数。
- 断点续传  
续传的时候，由客户端维护一个变量并传递给服务器注册到session中的restart_pos中。
- 配置解析  
做三张表，然后去查表解析config文件。用一个临时的指针指向表头，移动指针遍历表实现查找。

- 限速  
配置config中的w_upload_rate_max和bw_download_rate_max可以实现限速。具体的时间如下：session中有记录传输开始的时间，获得当前的时间，求得时间差（elapsed）；输出当前的传输速率，并和配置的最大速率比较，如果超出的话，根据公式算出需要睡眠的时间；睡眠完之后，需要更新开始传输的时间。
- 控制连接--空闲断开  
通过安装一个闹钟信号实现：在ftp进程中，**收到客户端命令之前，安装信号启动闹钟**。在闹钟信号到来之前，，没有收到客户端任何命令，则在SIGALRM信号处理程序中关闭控制连接，并给客户端421 TIMEPOUT的响应，并且退出会话。
- 数据连接--空闲断开
如果在数据传输的过程中，但是控制连接是空闲的，那么就不应该退出会话。实现方法：如果没有配置数据连接的空闲断开，那么就关掉之前控制连接设置的闹钟；如果配置了，那么就重新设置闹钟，就会自动覆盖掉之前的闹钟。在传输数据之前安装SIGALRM，并启动闹钟。在数据传输的过程中，收到SIGALRM信号，如果sess->data_process=0，则给客户端超时响应，并且退出会话；如果sess->data_process=1,将sess->data_process=0，重新安装SIGALRM，并启动闹钟。**该闹钟设置在模块中的获取连接函数中**，才能起作用。
- 最大连接数的限制  
在session结构体中，维护一个num_clients成员，在miniftp.c中，主线程序中，每次来一个客户端num_clients++。子进程在开启会话前要进行最大连接数限制的检查，小于最大连接数才能够开启会话。问题在于：**子进程退出的时候如何对num_clients进行维护呢？**
- 每IP连接数的限制
要实现每IP数登录的限制，需要实现两个Hash表：ip_count表、pid_ip表(调用专门的Hash模块实现)。在主线程序中，来一个客户端就登记对应的ip_count表，在其对应的父进程中登记pid_ip表（父进程可以拿到子进程的id号）。当一个客户端退出的时候，主线程序收到子进程结束发来的SIGCHLD信号会执行handle_sigchld函数。handle_sigchld()函数实现，首先调用waitpid()函数回收子进程。client_counts--(即最大连接数-1),通过pid查找ip，减少ip对应的count(通过调用drop_ip_count()函数实现),最后释放Hash表中pid_ip节点。
## 编译运行
1. 项目用makefile进行管理，在命令行`make`就可以生成二进制的可执行程序miniftpd
2. `./miniftpd`启动miniftp服务器，然后就可以用主机上的leapftp客户端去连启动的服务器。前提是保证虚拟机和主机的网是通的。在修改进程模型加入nobody进程之后，ip和port都要改成自己的配置。
3. tunable.c中的都是默认配置，如果需要修改请在miniftpd.conf中修改。
4. 项目在自动获取服务器所在平台的ip和端口还有一些问题，需要后续修改。
