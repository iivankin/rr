/*
 * Bench server on raw epoll: one thread, level-triggered epoll, see
 * ../SPEC.md. Also the proxy backend of every stack (json scenario).
 *
 * Level-triggered: a request/response client sends one request and
 * waits, so one read per readiness is enough and the extra read that
 * edge-triggered needs to see EAGAIN would be a wasted syscall per
 * request. Interest is EPOLLIN; a connection switches to EPOLLOUT only
 * while a response does not fit in the socket buffer.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "../c-common/http.h"
#include "../c-common/net.h"
#include "../c-common/pool.h"

#define NEVENTS   512
#define ACCEPTMAX 256           /* accepts per readiness */
#define RBUF      (REQMAX + BODYMAX)
#define UPBUF     (REQMAX + BODYMAX)

enum { K_LISTEN, K_EVENT, K_CONN, K_UP };
enum { UP_CONNECTING, UP_IDLE, UP_WAIT };

typedef struct Conn Conn;

typedef struct {
	int kind;               /* K_UP: epoll data.ptr points here */
	Conn *c;
	int fd;                 /* -1 until the first proxied request */
	int state;
	char *buf;              /* upstream response */
	size_t len, hend, clen;
	size_t hl;              /* client head built from the upstream one */
	char req[64];
	size_t reqlen;
} Up;

struct Conn {
	int kind;               /* K_CONN */
	int fd;
	int dead;
	int refs;               /* cpu job in flight */
	int busy;               /* answering the request at rbuf */
	int out;                /* EPOLLOUT armed instead of EPOLLIN */
	char *rbuf;
	size_t rlen;            /* bytes in rbuf */
	size_t scan;            /* head searched up to here */
	size_t hend;            /* head end of the current request, or 0 */
	size_t reqlen;          /* head + body of the current request */
	Req req;                /* parsed head, points into rbuf */
	struct iovec iov[2];
	int iovi, iovn;
	char *fbuf;             /* static body, freed once sent */
	Up up;
	Job job;
	char wbuf[HDRMAX + JSONMAX];
};

static void conn_serve(Conn *c);

static int epfd, scen;
static int kind_listen = K_LISTEN, kind_event = K_EVENT;
static char path[PATH_MAX];
static size_t pathdir;
static int logfd = -1;
static off_t logoff;
static struct sockaddr_storage backend;
static socklen_t backendlen;
static Conn **walq, **walq2;     /* filling, spare */
static size_t walqn, walqcap, walq2cap;
static Conn **dead;
static size_t deadn, deadcap;

static void *
xrealloc(void *p, size_t n)
{
	p = realloc(p, n);
	if (!p)
		die("out of memory");
	return p;
}

static void
ep_ctl(int op, int fd, unsigned ev, void *ptr)
{
	struct epoll_event e;

	e.events = ev;
	e.data.ptr = ptr;
	if (epoll_ctl(epfd, op, fd, &e) < 0)
		die("epoll_ctl: %m");
}

static void
conn_kill(Conn *c)
{
	if (c->dead)
		return;
	c->dead = 1;
	close(c->fd);
	if (c->up.fd >= 0)
		close(c->up.fd);
	if (deadn == deadcap) {
		deadcap = deadcap ? deadcap * 2 : 64;
		dead = xrealloc(dead, deadcap * sizeof(*dead));
	}
	dead[deadn++] = c;
}

static void
conn_free(Conn *c)
{
	free(c->rbuf);
	free(c->fbuf);
	free(c->up.buf);
	free(c);
}

/* Free the connections killed this turn: no event refers to them now. */
static void
sweep(void)
{
	size_t i, j;

	for (i = j = 0; i < deadn; i++) {
		if (dead[i]->refs)
			dead[j++] = dead[i];
		else
			conn_free(dead[i]);
	}
	deadn = j;
}

static void
conn_new(int fd)
{
	Conn *c;

	c = calloc(1, sizeof(*c));
	if (!c)
		die("out of memory");
	c->rbuf = malloc(RBUF);
	if (!c->rbuf)
		die("out of memory");
	c->kind = K_CONN;
	c->fd = fd;
	c->up.kind = K_UP;
	c->up.c = c;
	c->up.fd = -1;
	ep_ctl(EPOLL_CTL_ADD, fd, EPOLLIN, c);
}

/* The response is out: drop the request, take the next one. */
static void
finish(Conn *c)
{
	if (c->out) {
		ep_ctl(EPOLL_CTL_MOD, c->fd, EPOLLIN, c);
		c->out = 0;
	}
	free(c->fbuf);
	c->fbuf = NULL;
	c->rlen -= c->reqlen;
	if (c->rlen)
		memmove(c->rbuf, c->rbuf + c->reqlen, c->rlen);
	c->reqlen = c->hend = c->scan = 0;
	c->busy = 0;
}

/* Write c->iov; finish, or wait for EPOLLOUT, or kill. */
static void
send_resp(Conn *c)
{
	ssize_t n;
	size_t k;

	for (;;) {
		n = writev(c->fd, c->iov + c->iovi, c->iovn - c->iovi);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN) {
				conn_kill(c);
				return;
			}
			break;
		}
		while (n > 0) {
			k = c->iov[c->iovi].iov_len;
			if ((size_t)n < k) {
				c->iov[c->iovi].iov_base =
					(char *)c->iov[c->iovi].iov_base + n;
				c->iov[c->iovi].iov_len = k - (size_t)n;
				break;
			}
			n -= (ssize_t)k;
			c->iovi++;
		}
		if (c->iovi == c->iovn) {
			finish(c);
			return;
		}
		break;          /* partial: the socket buffer is full */
	}
	if (!c->out) {
		ep_ctl(EPOLL_CTL_MOD, c->fd, EPOLLOUT, c);
		c->out = 1;
	}
}

static void
respond1(Conn *c, const void *p, size_t n)
{
	c->iov[0].iov_base = (void *)p;
	c->iov[0].iov_len = n;
	c->iovi = 0;
	c->iovn = 1;
	send_resp(c);
}

static void
respond2(Conn *c, size_t hl, const void *body, size_t n)
{
	c->iov[0].iov_base = c->wbuf;
	c->iov[0].iov_len = hl;
	c->iov[1].iov_base = (void *)body;
	c->iov[1].iov_len = n;
	c->iovi = 0;
	c->iovn = n ? 2 : 1;
	send_resp(c);
}

static void
do_static(Conn *c, const char *name, size_t nl)
{
	ssize_t r;
	size_t n;
	int fd;

	if (!file_name_ok(name, nl) || pathdir + nl >= sizeof(path)) {
		respond1(c, RESP_404, sizeof(RESP_404) - 1);
		return;
	}
	memcpy(path + pathdir, name, nl);
	path[pathdir + nl] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		respond1(c, RESP_404, sizeof(RESP_404) - 1);
		return;
	}
	c->fbuf = malloc(FILEMAX);
	if (!c->fbuf)
		die("out of memory");
	n = 0;
	while (n < FILEMAX) {
		r = read(fd, c->fbuf + n, FILEMAX - n);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			respond1(c, RESP_404, sizeof(RESP_404) - 1);
			return;
		}
		if (r == 0)
			break;
		n += (size_t)r;
	}
	close(fd);
	respond2(c, http_head200(c->wbuf, CT_OCTET, sizeof(CT_OCTET) - 1, n),
	         c->fbuf, n);
}

static void
up_send(Conn *c)
{
	ssize_t n;

	c->up.len = c->up.hend = 0;
	do
		n = write(c->up.fd, c->up.req, c->up.reqlen);
	while (n < 0 && errno == EINTR);
	/* Some 40 bytes into an idle connection: never short or blocked. */
	if (n != (ssize_t)c->up.reqlen) {
		conn_kill(c);
		return;
	}
	c->up.state = UP_WAIT;
}

static void
up_connect(Conn *c)
{
	int fd;

	if (!c->up.buf) {
		c->up.buf = malloc(UPBUF);
		if (!c->up.buf)
			die("out of memory");
	}
	fd = socket(backend.ss_family,
	            SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		conn_kill(c);
		return;
	}
	nodelay(fd);
	c->up.fd = fd;
	if (connect(fd, (struct sockaddr *)&backend, backendlen) == 0) {
		ep_ctl(EPOLL_CTL_ADD, fd, EPOLLIN, &c->up);
		up_send(c);
		return;
	}
	if (errno != EINPROGRESS) {
		conn_kill(c);
		return;
	}
	c->up.state = UP_CONNECTING;
	ep_ctl(EPOLL_CTL_ADD, fd, EPOLLOUT, &c->up);
}

static void
do_proxy(Conn *c, uint32_t id)
{
	c->up.reqlen = upstream_request(c->up.req, id);
	if (c->up.fd < 0)
		up_connect(c);
	else
		up_send(c);
}

static void
up_event(Up *u, unsigned ev)
{
	Conn *c;
	const char *ct;
	size_t ctlen, from;
	ssize_t n;
	char junk[64];
	int err;
	socklen_t el;

	c = u->c;
	if (c->dead)
		return;
	if (u->state == UP_CONNECTING) {
		if (!(ev & (EPOLLOUT | EPOLLERR | EPOLLHUP)))
			return;
		err = 0;
		el = sizeof(err);
		if (getsockopt(u->fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 ||
		    err) {
			conn_kill(c);
			return;
		}
		ep_ctl(EPOLL_CTL_MOD, u->fd, EPOLLIN, u);
		up_send(c);
		return;
	}
	if (u->state != UP_WAIT) {
		/* Idle: only EOF or an error can come; either ends it. */
		n = read(u->fd, junk, sizeof(junk));
		if (n < 0 && (errno == EAGAIN || errno == EINTR))
			return;
		conn_kill(c);
		return;
	}
	n = read(u->fd, u->buf + u->len, UPBUF - u->len);
	if (n < 0 && (errno == EAGAIN || errno == EINTR))
		return;
	if (n <= 0) {
		conn_kill(c);
		return;
	}
	from = u->len;
	u->len += (size_t)n;
	if (!u->hend) {
		u->hend = http_head_end(u->buf, u->len, from);
		if (!u->hend) {
			if (u->len >= REQMAX)
				conn_kill(c);
			return;
		}
		if (!http_parse_resp(u->buf, u->hend, &ct, &ctlen, &u->clen)) {
			conn_kill(c);
			return;
		}
		/* The head stays in u->buf: copy Content-Type now. */
		u->hl = http_head200(c->wbuf, ct, ctlen, u->clen);
	}
	if (u->len < u->hend + u->clen)
		return;
	if (u->len > u->hend + u->clen) {
		conn_kill(c);
		return;
	}
	u->state = UP_IDLE;
	respond2(c, u->hl, u->buf + u->hend, u->clen);
	if (!c->dead && !c->busy)
		conn_serve(c);
}

static void
wal_push(Conn *c)
{
	if (walqn == walqcap) {
		walqcap = walqcap ? walqcap * 2 : 256;
		walq = xrealloc(walq, walqcap * sizeof(*walq));
	}
	walq[walqn++] = c;
}

/* Append iov[0..n) at logoff, all of it or die. */
static void
wal_write(struct iovec *iov, int n)
{
	ssize_t w;

	while (n > 0) {
		w = pwritev(logfd, iov, n, logoff);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			die("wal write: %m");
		}
		logoff += w;
		while (n > 0 && (size_t)w >= iov->iov_len) {
			w -= (ssize_t)iov->iov_len;
			iov++;
			n--;
		}
		if (n > 0) {
			iov->iov_base = (char *)iov->iov_base + w;
			iov->iov_len -= (size_t)w;
		}
	}
}

/* Group commit: the appends of this turn, one fdatasync, then answers. */
static void
wal_flush(void)
{
	struct iovec iov[IOV_MAX];
	Conn **q, *c;
	size_t i, n, qcap;
	int k;

	/* Answers can queue new appends: they go to the spare queue. */
	q = walq;
	n = walqn;
	qcap = walqcap;
	walq = walq2;
	walqcap = walq2cap;
	walq2 = NULL;
	walqn = 0;
	for (i = 0; i < n; i += (size_t)k) {
		for (k = 0; k < IOV_MAX && i + (size_t)k < n; k++) {
			c = q[i + (size_t)k];
			iov[k].iov_base = c->rbuf + c->hend;
			iov[k].iov_len = c->reqlen - c->hend;
		}
		wal_write(iov, k);
	}
	while (fdatasync(logfd) < 0)
		if (errno != EINTR)
			die("fdatasync: %m");
	for (i = 0; i < n; i++) {
		c = q[i];
		if (c->dead)
			continue;
		respond1(c, RESP_OK, sizeof(RESP_OK) - 1);
		if (!c->dead && !c->busy)
			conn_serve(c);
	}
	walq2 = q;
	walq2cap = qcap;
}

static void
route(Conn *c, const Req *r)
{
	const char *a;
	size_t al;
	uint32_t v;

	if (r->method == M_GET) {
		if ((scen == S_JSON || scen == S_CPU) &&
		    path_arg(r, "/user/", 6, &a, &al) && parse_u32(a, al, &v)) {
			respond1(c, c->wbuf, json_response(c->wbuf, v));
			return;
		}
		if (scen == S_STATIC && path_arg(r, "/file/", 6, &a, &al)) {
			do_static(c, a, al);
			return;
		}
		if (scen == S_PROXY && path_arg(r, "/proxy/", 7, &a, &al) &&
		    parse_u32(a, al, &v)) {
			do_proxy(c, v);
			return;
		}
		if (scen == S_CPU && path_arg(r, "/hash/", 6, &a, &al) &&
		    parse_u32(a, al, &v)) {
			c->job.owner = c;
			c->job.n = v;
			c->refs = 1;
			pool_submit(&c->job);
			return;
		}
	} else if (r->method == M_POST && scen == S_WAL &&
	           r->pathlen == 4 && !memcmp(r->path, "/log", 4)) {
		wal_push(c);
		return;
	}
	respond1(c, RESP_404, sizeof(RESP_404) - 1);
}

/* Answer the requests in rbuf while each is answered at once. */
static void
conn_serve(Conn *c)
{
	while (!c->busy && !c->dead) {
		if (!c->hend) {
			c->hend = http_head_end(c->rbuf, c->rlen, c->scan);
			if (!c->hend) {
				c->scan = c->rlen;
				if (c->rlen >= REQMAX)
					conn_kill(c);
				return;
			}
			if (!http_parse(c->rbuf, c->hend, &c->req)) {
				conn_kill(c);
				return;
			}
		}
		if (c->rlen < c->hend + c->req.clen)
			return;
		c->reqlen = c->hend + c->req.clen;
		c->busy = 1;
		route(c, &c->req);
	}
}

static void
conn_event(Conn *c)
{
	ssize_t n;

	if (c->dead)
		return;
	if (c->out) {
		send_resp(c);
		if (!c->dead && !c->busy)
			conn_serve(c);
		return;
	}
	if (c->rlen == RBUF) {
		conn_kill(c);
		return;
	}
	n = read(c->fd, c->rbuf + c->rlen, RBUF - c->rlen);
	if (n < 0 && (errno == EAGAIN || errno == EINTR))
		return;
	if (n <= 0) {
		conn_kill(c);
		return;
	}
	c->rlen += (size_t)n;
	if (!c->busy)
		conn_serve(c);
}

static void
accept_all(int lfd)
{
	int i, fd;

	for (i = 0; i < ACCEPTMAX; i++) {
		fd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			return;  /* EAGAIN, or out of descriptors: retry later */
		}
		nodelay(fd);
		conn_new(fd);
	}
}

static void
cpu_done(void)
{
	uint64_t v;
	Job *j, *next;
	Conn *c;

	while (read(pool.efd, &v, sizeof(v)) < 0 && errno == EINTR)
		;
	for (j = pool_take(); j; j = next) {
		next = j->next;
		c = j->owner;
		c->refs = 0;
		if (c->dead)
			continue;
		respond1(c, c->wbuf, u64_response(c->wbuf, j->result));
		if (!c->dead && !c->busy)
			conn_serve(c);
	}
}

int
main(int argc, char *argv[])
{
	struct epoll_event ev[NEVENTS];
	const char *s;
	int lfd, efd, n, i, *k;

	if (argc != 3)
		die("usage: server SCENARIO PORT");
	scen = scenario(argv[1]);
	signal(SIGPIPE, SIG_IGN);
	raise_nofile();
	if (scen == S_STATIC) {
		s = getenv("FILES");
		if (!s)
			die("static needs FILES=dir");
		pathdir = strlen(s);
		if (pathdir + 2 > sizeof(path))
			die("FILES too long");
		memcpy(path, s, pathdir);
		path[pathdir++] = '/';
	}
	if (scen == S_PROXY)
		resolve_backend(&backend, &backendlen);
	if (scen == S_WAL) {
		s = getenv("LOG");
		if (!s)
			die("wal needs LOG=path");
		logfd = open(s, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		             0644);
		if (logfd < 0)
			die("open %s: %m", s);
	}
	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0)
		die("epoll_create1: %m");
	if (scen == S_CPU) {
		efd = pool_start(EFD_NONBLOCK);
		if (efd < 0)
			die("cpu pool: %m");
		ep_ctl(EPOLL_CTL_ADD, efd, EPOLLIN, &kind_event);
	}
	lfd = listen_on(argv[2], SOCK_NONBLOCK);
	ep_ctl(EPOLL_CTL_ADD, lfd, EPOLLIN, &kind_listen);
	say_ready();

	for (;;) {
		n = epoll_wait(epfd, ev, NEVENTS, -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			die("epoll_wait: %m");
		}
		for (i = 0; i < n; i++) {
			k = ev[i].data.ptr;
			switch (*k) {
			case K_CONN:
				conn_event((Conn *)k);
				break;
			case K_UP:
				up_event((Up *)k, ev[i].events);
				break;
			case K_LISTEN:
				accept_all(lfd);
				break;
			case K_EVENT:
				cpu_done();
				break;
			}
		}
		while (walqn)
			wal_flush();
		sweep();
	}
}
