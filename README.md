# 弱密码查询服务

weakpassd 程序基于GPL v3发布。

特点：

* 仅仅一个进程，占用内存约9MB，启动后不再读写任何文件，每秒钟可以响应超1万次查询
* 使用epoll高效接口，单进程支持超1万并发连接（需要使用ulimit -n 10240设置单进程可打开的文件数）

演示站点（请单击如下URL测试）：

* 查询弱密码 [http://ip.ustc.edu.cn/weak_pass_md5/e10adc3949ba59abbe56e057f20f883e](http://ip.ustc.edu.cn/weak_pass_md5/e10adc3949ba59abbe56e057f20f883e)

命令行：
```
Usage:
   weakpassd [ -d ] [ -f ] [ -6 ] [ -w weak_pass_filename ] [ tcp_port ]
        -d debug
        -f fork and do
        -6 support ipv6
	-w weak_pass_filename, default is weak_pss.txt
        default port is 80
```

## 独立进程运行

```
cd /usr/src
git clone https://github.com/bg6cq/weakpass
cd weakpass
make

./weakpassd -f 90
```

如果需要查看运行的调试输出，可以使用

```
./weakpassd -f -d 90
```

上面的90是提供服务的tcp端口，访问 http://server_ip:90/md5sum 即可返回弱密码信息

