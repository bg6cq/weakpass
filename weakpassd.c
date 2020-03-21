/*
weak_pass.txt

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/md5.h>

#include "uthash.h"

#define MAXEVENTS 64

#define MAXLEN 1024

int port = 80;
int fork_and_do = 0;
int debug = 0;
int ipv6 = 0;
char weak_pass_filename[MAXLEN];

char *http_head = "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nServer: web server by james@ustc.edu.cn\r\n\r\n";

struct pass_struct {
	char md5[33];
	char *pass;
	UT_hash_handle hh;	/* makes this structure hashable */
};

struct pass_struct *all_pass = NULL;

const char *hexDigits = "0123456789abcdef";

char *md5_sum(char *pass)
{
	unsigned char result[17];
	static char md5_r[33];
	char *dest = md5_r;
	int i;

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, pass, strlen(pass));
	MD5_Final(result, &ctx);
	for (i = 0; i < 16; i++) {
		*dest++ = hexDigits[result[i] >> 4];
		*dest++ = hexDigits[result[i] & 0x0F];
	}
	*dest = 0;
	return md5_r;
}

void add_pass(char *pass)
{
	struct pass_struct *s;
	char *md5_r;
	md5_r = md5_sum(pass);

#ifdef DEBUG
	printf("pass: %s, md5: %s ", pass, md5_r);
#endif

	// 先查找是否已经加过了
	HASH_FIND_STR(all_pass, md5_r, s);

	if (s) {
		printf("%s duplicated\n", pass);
		return;
	}

	s = malloc(sizeof(struct pass_struct));
	if (s == NULL) {
		printf("malloc error, exit\n");
		exit(-1);
	}
	s->pass = malloc(strlen(pass) + 1);
	if (s->pass == NULL) {
		printf("malloc error, exit\n");
		exit(-1);
	}
	strcpy(s->pass, pass);
	strcpy(s->md5, md5_r);
	HASH_ADD_STR(all_pass, md5, s);
#ifdef DEBUG
	printf("added\n");
#endif
}

int total_wk_pass = 0;

void load_wk_pass(char *wk_pass)
{
	FILE *fp;
	char buf[MAXLEN];
	printf("loading weak password file %s\n", wk_pass);
	fp = fopen(wk_pass, "r");
	if (fp == NULL) {
		printf("%s open error\n", wk_pass);
		exit(0);
	}
	while (fgets(buf, MAXLEN, fp)) {
		if (strlen(buf) < 1)
			continue;
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = 0;
		add_pass(buf);
		total_wk_pass++;
	}
	fclose(fp);
	printf("loaded %d weak passwords\n", total_wk_pass);
}

void find(char *md5, char *result, int len)
{
	struct pass_struct *s;
	char *p;
	md5[32] = 0;
	if (debug >= 2)
		printf("find: %s\n", md5);
	p = md5;
	while (*p) {
		*p = tolower(*p);
		p++;
	}

	HASH_FIND_STR(all_pass, md5, s);
	if (s) {
		int l;
		if (debug >= 2)
			printf("WK %s %s\n", s->pass, md5);
		l = snprintf(result, len, "{\"weak\": \"true\", \"password\": \"");
		p = s->pass;
		while (*p) {
			if (l >= len - 5) {
				result[l] = '"';
				result[l + 1] = '}';
				result[l + 2] = 0;
				return;
			}
			switch (*p) {
			case '"':
				result[l] = '\\';
				result[l + 1] = '"';
				l++;
				break;
			case '/':
				result[l] = '\\';
				result[l + 1] = '/';
				l++;
				break;
			case '\t':
				result[l] = '\\';
				result[l + 1] = 't';
				l++;
				break;
			case '\\':
				result[l] = '\\';
				result[l + 1] = '\\';
				l++;
				break;
			default:
				result[l] = *p;
			}
			l++;
			p++;
		}
		result[l] = '"';
		result[l + 1] = '}';
		result[l + 2] = 0;
		return;
	}

	snprintf(result, len, "{\"weak\": \"false\", \"password\": \"\"}");
	return;
}

void respond(int cfd, char *mesg)
{
	char buf[MAXLEN], *p = mesg;
	char result[MAXLEN];
	int len = 0;

	if (debug >= 2)
		printf("From Client(fd %d):\n%s##END\n", cfd, mesg);

	buf[0] = 0;
	if (memcmp(p, "GET /", 5) == 0) {
		if (memcmp(p + 5, "favicon.ico", 11) == 0)
			len = snprintf(buf, MAXLEN, "HTTP/1.0 404 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n");
		else {
			find(p + 5, result, 128);
			if (result[0])
				len = snprintf(buf, MAXLEN, "%s%s", http_head, result);
			else
				len = snprintf(buf, MAXLEN, "%s未知", http_head);
		}
	}

	if (debug >= 2)
		printf("Send to Client(fd %d):\n%s##END\n", cfd, buf);
	write(cfd, buf, len);
}

int set_socket_non_blocking(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -1;
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0)
		return -1;
	return 0;
}

void set_socket_keepalive(int fd)
{
	int keepalive = 1;	// 开启keepalive属性
	int keepidle = 5;	// 如该连接在60秒内没有任何数据往来,则进行探测
	int keepinterval = 5;	// 探测时发包的时间间隔为5 秒
	int keepcount = 3;	// 探测尝试的次数。如果第1次探测包就收到响应了,则后2次的不再发
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive));
	setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, (void *)&keepidle, sizeof(keepidle));
	setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepinterval, sizeof(keepinterval));
	setsockopt(fd, SOL_TCP, TCP_KEEPCNT, (void *)&keepcount, sizeof(keepcount));
}

void usage(void)
{
	printf("Usage:\n");
	printf("   weakpassd [ -d debug_level ] [ -f ] [ -6 ] [ -w weak_pass_filename ] [ tcp_port ]\n");
	printf("        -d debug, level 1: print socket op, 2: print msg\n");
	printf("        -f fork and do\n");
	printf("        -6 support ipv6\n");
	printf("        -w weak_pass_filename, default is weak_pass.txt\n");
	printf("        default port is 80\n");
	exit(0);
}

int bind_and_listen(void)
{
	int listenfd;
	int enable = 1;

	if (ipv6)
		listenfd = socket(AF_INET6, SOCK_STREAM, 0);
	else
		listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		perror("error: socket");
		exit(-1);
	}
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("error: setsockopt(SO_REUSEADDR)");
		exit(-1);
	}
	if (ipv6) {
		static struct sockaddr_in6 serv_addr6;
		memset(&serv_addr6, 0, sizeof(serv_addr6));
		serv_addr6.sin6_family = AF_INET6;
		serv_addr6.sin6_port = htons(port);
		if (bind(listenfd, (struct sockaddr *)&serv_addr6, sizeof(serv_addr6)) < 0) {
			perror("error: bind");
			exit(-1);
		}
	} else {
		static struct sockaddr_in serv_addr;
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		serv_addr.sin_port = htons(port);
		if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
			perror("error: bind");
			exit(-1);
		}
	}
	if (set_socket_non_blocking(listenfd) < 0) {
		perror("error: set_socket_non_blocking");
		exit(-1);
	}
	if (listen(listenfd, 64) < 0) {
		perror("error: listen");
		exit(-1);
	}
	return listenfd;
}

int main(int argc, char *argv[])
{
	int listenfd, efd;
	int idle_fd = open("/dev/null", O_RDONLY);	// fd for accept no file err
	struct epoll_event event, *events;

	strcpy(weak_pass_filename, "weak_pass.txt");

	int c;
	while ((c = getopt(argc, argv, "d:w:f6h")) != EOF)
		switch (c) {
		case 'd':
			debug = atoi(optarg);;
			break;
		case 'w':
			strncpy(weak_pass_filename, optarg, MAXLEN - 1);
			break;
		case 'f':
			fork_and_do = 1;
			break;
		case '6':
			ipv6 = 1;
			break;
		case 'h':
			usage();

		};
	if (optind == argc - 1)
		port = atoi(argv[optind]);
	if (port < 0 || port > 65535) {
		printf("Invalid port number %d, please try [1,65535]", port);
		exit(-1);
	}

	(void)signal(SIGCLD, SIG_IGN);
	(void)signal(SIGHUP, SIG_IGN);
	setvbuf(stdout, NULL, _IONBF, 0);

	if (fork_and_do) {
		if (debug)
			printf("I am parent, pid: %d\n", getpid());
		while (1) {
			int pid = fork();
			if (pid == 0)	// child do the job
				break;
			else {
				if (debug)
					printf("I am parent, waiting for child...\n");
				wait(NULL);
			}
			if (debug)
				printf("child exit? I will restart it.\n");
			sleep(2);
		}
		if (debug)
			printf("I am child, I am doing the job\n");
	}
	printf("web server started at port: %d, my pid: %d\n", port, getpid());

	load_wk_pass(weak_pass_filename);

	listenfd = bind_and_listen();
	if ((efd = epoll_create1(0)) < 0) {
		perror("error: epoll_create1");
		exit(-1);
	}
	event.data.fd = listenfd;
	event.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, listenfd, &event) < 0) {
		perror("error: epoll_ctl_add of listenfd");
		exit(-1);
	}
	/* Buffer where events are returned */
	events = calloc(MAXEVENTS, sizeof event);
	if (events == NULL) {
		perror("error: calloc memory");
		exit(-1);
	}
	// Event Loop 
	while (1) {
		int n, i;
		n = epoll_wait(efd, events, MAXEVENTS, -1);
		for (i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
				/* An error has occured on this fd, or the socket is not
				 * ready for reading (why were we notified then?) */
				printf("epollerr or epollhup event of fd %d\n", events[i].data.fd);
				close(events[i].data.fd);
				continue;
			}
			if (!(events[i].events & EPOLLIN)) {
				printf("error: unknow event of fd %d\n", events[i].data.fd);
				close(events[i].data.fd);
				continue;
			}
			if (listenfd == events[i].data.fd) {
				/* notification on the listening socket, which
				 * means one or more incoming connections. */
				while (1) {
					int infd;
					infd = accept(listenfd, NULL, 0);
					if (infd == -1) {
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK))	/*  all incoming connections processed. */
							break;
						else if ((errno == EMFILE) || (errno == ENFILE)) {
							perror("error: first accept");
							close(idle_fd);
							infd = accept(listenfd, NULL, 0);
							if (infd == -1) {
								if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {	/*  all incoming connections processed. */
									idle_fd = open("/dev/null", O_RDONLY);
									break;
								} else {
									perror("error: sencond accept");
									exit(-1);
								}
							}
							close(infd);
							idle_fd = open("/dev/null", O_RDONLY);
							continue;
						} else {
							perror("error: accept new client");
							exit(-1);
						}
					}
					if (debug) {
						struct sockaddr_storage in_addr;
						socklen_t in_len = sizeof(in_addr);
						char hbuf[INET6_ADDRSTRLEN];

						getpeername(infd, (struct sockaddr *)&in_addr, &in_len);
						if (in_addr.ss_family == AF_INET6) {
							struct sockaddr_in6 *r = (struct sockaddr_in6 *)&in_addr;
							inet_ntop(AF_INET6, &r->sin6_addr, hbuf, sizeof(hbuf));
							printf("new connection on fd %d " "(host=%s, port=%d)\n", infd, hbuf, ntohs(r->sin6_port));
						} else if (in_addr.ss_family == AF_INET) {
							struct sockaddr_in *r = (struct sockaddr_in *)&in_addr;
							inet_ntop(AF_INET, &r->sin_addr, hbuf, sizeof(hbuf));
							printf("new connection on fd %d " "(host=%s, port=%d)\n", infd, hbuf, ntohs(r->sin_port));
						}
					}

					/* set the incoming socket non-blocking and add it to the list of fds to monitor. */
					if (set_socket_non_blocking(infd) < 0) {
						perror("error: set_socket_non_blocking of new client");
						close(infd);
						continue;
					}
					set_socket_keepalive(infd);
					event.data.fd = infd;
					event.events = EPOLLIN | EPOLLET;
					if (epoll_ctl(efd, EPOLL_CTL_ADD, infd, &event) < 0) {
						perror("error: epoll_ctl_add new client");
						close(infd);
					}
				}
				continue;
			} else if (events[i].events & EPOLLIN) {
				/* new data on the fd waiting to be read.
				 *
				 * We only read the first packet, for normal http client, it's OK */
				ssize_t count;
				char buf[MAXLEN];

				count = read(events[i].data.fd, buf, MAXLEN - 1);
				if (count > 0) {
					buf[count] = 0;
					respond(events[i].data.fd, buf);
				}
				if (debug)
					printf("close fd %d\n", events[i].data.fd);
				shutdown(events[i].data.fd, SHUT_RDWR);
				close(events[i].data.fd);
			}
		}
	}
}
