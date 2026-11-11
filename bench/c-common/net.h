/* Startup helpers shared by the C bench servers. */
#ifndef BENCH_NET_H
#define BENCH_NET_H

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

enum { S_JSON, S_STATIC, S_PROXY, S_WAL, S_CPU };

static void
die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static int
scenario(const char *s)
{
	static const char *const names[] = {
		"json", "static", "proxy", "wal", "cpu"
	};
	int i;

	for (i = 0; i < 5; i++)
		if (!strcmp(s, names[i]))
			return i;
	die("unknown scenario %s", s);
	return -1;
}

/* Raise the descriptor limit to the hard limit; returns the new one. */
static long
raise_nofile(void)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		return 1024;
	if (rl.rlim_cur < rl.rlim_max) {
		rl.rlim_cur = rl.rlim_max;
		setrlimit(RLIMIT_NOFILE, &rl);
		getrlimit(RLIMIT_NOFILE, &rl);
	}
	return rl.rlim_cur > 1 << 20 ? 1 << 20 : (long)rl.rlim_cur;
}

static void
nodelay(int fd)
{
	int one;

	one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

/* 0.0.0.0:port, SO_REUSEADDR, backlog 4096. flags: SOCK_NONBLOCK or 0. */
static int
listen_on(const char *port, int flags)
{
	struct sockaddr_in a;
	int fd, one;
	long p;
	char *e;

	p = strtol(port, &e, 10);
	if (*e || p <= 0 || p > 65535)
		die("bad port %s", port);
	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | flags, 0);
	if (fd < 0)
		die("socket: %m");
	one = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		die("SO_REUSEADDR: %m");
	nodelay(fd);
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons((unsigned short)p);
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0)
		die("bind %s: %m", port);
	if (listen(fd, 4096) < 0)
		die("listen: %m");
	return fd;
}

/* $BACKEND host:port, resolved once at startup. */
static void
resolve_backend(struct sockaddr_storage *ss, socklen_t *len)
{
	struct addrinfo hints, *res;
	char host[256], *colon;
	const char *b;
	int rc;

	b = getenv("BACKEND");
	if (!b || strlen(b) >= sizeof(host))
		die("proxy needs BACKEND=host:port");
	strcpy(host, b);
	colon = strrchr(host, ':');
	if (!colon)
		die("BACKEND %s: no port", b);
	*colon = '\0';
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	rc = getaddrinfo(host, colon + 1, &hints, &res);
	if (rc)
		die("BACKEND %s: %s", b, gai_strerror(rc));
	memcpy(ss, res->ai_addr, res->ai_addrlen);
	*len = res->ai_addrlen;
	freeaddrinfo(res);
}

static void
say_ready(void)
{
	fputs("ready\n", stdout);
	fflush(stdout);
}

#endif
