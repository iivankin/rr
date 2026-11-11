/*
 * Bench server on io_uring (liburing): one thread, see ../SPEC.md.
 *
 * The ring is SINGLE_ISSUER | DEFER_TASKRUN: completions run only when
 * the loop asks for them, in one io_uring_enter per turn that also
 * submits everything the previous turn queued. Accept is multishot;
 * every socket has one multishot recv armed on a provided buffer ring,
 * whose buffers are copied into the connection's request buffer and
 * given back at once. Static files go openat -> read -> close as one
 * linked chain on a direct descriptor (slot = connection id), wal is a
 * write linked to an fsync(DATASYNC) for each batch, cpu answers come
 * back through a read of the pool's eventfd on the ring.
 *
 * A connection counts the ring operations that refer to it (inflight).
 * Killing it shuts its sockets down, which completes the recvs; it is
 * closed and its slot reused only when the last completion is in.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "../c-common/http.h"
#include "../c-common/net.h"
#include "../c-common/pool.h"

#define SQ_ENTRIES 4096
#define CQ_ENTRIES 16384
#define NBUF       1024         /* provided recv buffers */
#define BUFSZ      4096
#define BGID       0
#define MAXCONN    65536
#define RBUF       (REQMAX + BODYMAX)
#define UPBUF      (REQMAX + BODYMAX)
#define TAGMASK    15ull

/* user_data: a connection pointer (16-aligned) or 0, | one of these. */
enum {
	T_ACCEPT = 1, T_EVENT, T_WALW, T_WALS,
	T_RECV, T_SEND, T_UPCONN, T_UPSEND, T_UPRECV,
	T_FOPEN, T_FREAD, T_FCLOSE
};
enum { UP_IDLE, UP_WAIT };

typedef struct Conn Conn;
struct Conn {
	int fd;
	int id;                 /* index in conns, direct descriptor slot */
	int dead;
	int inflight;           /* ring operations and jobs that refer here */
	int busy;               /* answering the request at rbuf */
	char *rbuf;
	size_t rlen, scan, hend, reqlen;
	Req req;
	struct iovec iov[2];
	int iovi, iovn;
	struct msghdr msg;
	char *fbuf;             /* static body, freed once sent */
	char *path;
	int fleft, openres, readres;
	int upfd;               /* -1 until the first proxied request */
	int upstate;
	char *upbuf;
	size_t uplen, uphend, upclen, uphl;
	char upreq[64];
	size_t upreqlen;
	Job job;
	char wbuf[HDRMAX + JSONMAX];
};

static void conn_serve(Conn *c);

static struct io_uring ring;
static struct io_uring_buf_ring *br;
static char *bufs;
static int scen, lfd, logfd = -1, efd = -1;
static uint64_t evbuf;
static Conn **conns;
static int *freeids, nfree, nslots;
static const char *filesdir;
static size_t filesdirlen;
static struct sockaddr_storage backend;
static socklen_t backendlen;

/* wal: one batch in flight, the next one filling. */
static struct {
	char *buf;
	size_t len, cap;
	Conn **q;
	size_t n, qcap;
} wal[2];
static int walfill, walbusy;
static off_t logoff;

static void *
xrealloc(void *p, size_t n)
{
	p = realloc(p, n);
	if (!p)
		die("out of memory");
	return p;
}

/* n consecutive SQEs, so that a linked chain is never split. */
static struct io_uring_sqe *
sqe_get(unsigned n)
{
	struct io_uring_sqe *s;

	if (io_uring_sq_space_left(&ring) < n)
		io_uring_submit(&ring);
	s = io_uring_get_sqe(&ring);
	if (!s)
		die("sq full");
	return s;
}

static void
sqe_tag(struct io_uring_sqe *s, Conn *c, unsigned tag)
{
	io_uring_sqe_set_data64(s, (uint64_t)(uintptr_t)c | tag);
	if (c)
		c->inflight++;
}

static void
buf_recycle(unsigned bid)
{
	io_uring_buf_ring_add(br, bufs + (size_t)bid * BUFSZ, BUFSZ, bid,
	                      io_uring_buf_ring_mask(NBUF), 0);
	io_uring_buf_ring_advance(br, 1);
}

static void
arm_recv(Conn *c, int fd, unsigned tag)
{
	struct io_uring_sqe *s;

	s = sqe_get(1);
	io_uring_prep_recv_multishot(s, fd, NULL, 0, 0);
	s->flags |= IOSQE_BUFFER_SELECT;
	s->buf_group = BGID;
	sqe_tag(s, c, tag);
}

static void
arm_accept(void)
{
	struct io_uring_sqe *s;

	s = sqe_get(1);
	io_uring_prep_multishot_accept(s, lfd, NULL, NULL, SOCK_CLOEXEC);
	sqe_tag(s, NULL, T_ACCEPT);
}

static void
arm_event(void)
{
	struct io_uring_sqe *s;

	s = sqe_get(1);
	io_uring_prep_read(s, efd, &evbuf, sizeof(evbuf), 0);
	sqe_tag(s, NULL, T_EVENT);
}

static void
conn_kill(Conn *c)
{
	if (c->dead)
		return;
	c->dead = 1;
	shutdown(c->fd, SHUT_RDWR);
	if (c->upfd >= 0)
		shutdown(c->upfd, SHUT_RDWR);
}

/* After each completion of c: release it when nothing refers to it. */
static void
conn_put(Conn *c)
{
	if (!c->dead || c->inflight)
		return;
	close(c->fd);
	if (c->upfd >= 0)
		close(c->upfd);
	free(c->fbuf);
	c->fbuf = NULL;
	freeids[nfree++] = c->id;
}

static void
conn_new(int fd)
{
	Conn *c;
	int id;

	if (!nfree) {
		close(fd);
		return;
	}
	id = freeids[--nfree];
	c = conns[id];
	if (!c) {
		c = calloc(1, sizeof(*c));
		if (!c || ((uintptr_t)c & TAGMASK))
			die("conn alloc");
		c->rbuf = malloc(RBUF);
		if (!c->rbuf)
			die("out of memory");
		c->id = id;
		conns[id] = c;
	}
	c->fd = fd;
	c->dead = c->inflight = c->busy = 0;
	c->rlen = c->scan = c->hend = c->reqlen = 0;
	c->upfd = -1;
	c->upstate = UP_IDLE;
	nodelay(fd);
	arm_recv(c, fd, T_RECV);
}

/*
 * MSG_WAITALL: the kernel finishes a short send itself (Linux 5.19+)
 * instead of posting a completion per socket-buffer-full; on_send
 * still continues a short one.
 */
static void
send_resp(Conn *c)
{
	struct io_uring_sqe *s;

	s = sqe_get(1);
	if (c->iovn - c->iovi == 1) {
		io_uring_prep_send(s, c->fd, c->iov[c->iovi].iov_base,
		                   c->iov[c->iovi].iov_len,
		                   MSG_NOSIGNAL | MSG_WAITALL);
	} else {
		memset(&c->msg, 0, sizeof(c->msg));
		c->msg.msg_iov = c->iov + c->iovi;
		c->msg.msg_iovlen = (size_t)(c->iovn - c->iovi);
		io_uring_prep_sendmsg(s, c->fd, &c->msg,
		                      MSG_NOSIGNAL | MSG_WAITALL);
	}
	sqe_tag(s, c, T_SEND);
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
respond404(Conn *c)
{
	respond1(c, RESP_404, sizeof(RESP_404) - 1);
}

/* The response is out: drop the request, take the next one. */
static void
finish(Conn *c)
{
	free(c->fbuf);
	c->fbuf = NULL;
	c->rlen -= c->reqlen;
	if (c->rlen)
		memmove(c->rbuf, c->rbuf + c->reqlen, c->rlen);
	c->reqlen = c->hend = c->scan = 0;
	c->busy = 0;
}

static void
on_send(Conn *c, int res)
{
	size_t n, k;

	c->inflight--;
	if (c->dead)
		return;
	if (res <= 0) {
		conn_kill(c);
		return;
	}
	n = (size_t)res;
	while (n > 0 && c->iovi < c->iovn) {
		k = c->iov[c->iovi].iov_len;
		if (n < k) {
			c->iov[c->iovi].iov_base =
				(char *)c->iov[c->iovi].iov_base + n;
			c->iov[c->iovi].iov_len = k - n;
			break;
		}
		n -= k;
		c->iovi++;
	}
	if (c->iovi < c->iovn) {
		send_resp(c);
		return;
	}
	finish(c);
	conn_serve(c);
}

/* A multishot recv completion on c's client or upstream socket. */
static int
recv_take(Conn *c, struct io_uring_cqe *cqe, char *dst, size_t *len,
          size_t cap)
{
	unsigned bid;
	int ok;

	ok = 1;
	if (!(cqe->flags & IORING_CQE_F_MORE))
		c->inflight--;
	if (cqe->flags & IORING_CQE_F_BUFFER) {
		bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
		if (cqe->res > 0 && !c->dead) {
			if (!dst || *len + (size_t)cqe->res > cap) {
				ok = 0;
			} else {
				memcpy(dst + *len, bufs + (size_t)bid * BUFSZ,
				       (size_t)cqe->res);
				*len += (size_t)cqe->res;
			}
		}
		buf_recycle(bid);
	}
	if (!ok)
		conn_kill(c);
	return ok;
}

/* Whether the recv must be armed again, or kill on EOF and errors. */
static int
recv_continue(Conn *c, struct io_uring_cqe *cqe)
{
	if (c->dead)
		return 0;
	if (cqe->res > 0 || cqe->res == -ENOBUFS) {
		return !(cqe->flags & IORING_CQE_F_MORE);
	}
	conn_kill(c);
	return 0;
}

static void
on_recv(Conn *c, struct io_uring_cqe *cqe)
{
	recv_take(c, cqe, c->rbuf, &c->rlen, RBUF);
	if (recv_continue(c, cqe))
		arm_recv(c, c->fd, T_RECV);
	if (!c->dead && cqe->res > 0 && !c->busy)
		conn_serve(c);
}

static void
on_static(Conn *c, int tag, int res)
{
	c->inflight--;
	if (tag == T_FOPEN)
		c->openres = res;
	else if (tag == T_FREAD)
		c->readres = res;
	if (--c->fleft || c->dead)
		return;
	if (c->openres < 0 || c->readres < 0) {
		respond404(c);
		return;
	}
	respond2(c, http_head200(c->wbuf, CT_OCTET, sizeof(CT_OCTET) - 1,
	         (size_t)c->readres), c->fbuf, (size_t)c->readres);
}

/*
 * openat -> read -> close on the direct descriptor c->id. The read is
 * hard-linked to the close: a read shorter than FILEMAX (every file
 * under 1 MiB) breaks a plain link, and the slot must be closed anyway.
 * A failed open cancels both.
 */
static void
do_static(Conn *c, const char *name, size_t nl)
{
	struct io_uring_sqe *s;

	if (!file_name_ok(name, nl)) {
		respond404(c);
		return;
	}
	if (!c->path) {
		c->path = malloc(filesdirlen + 257);
		if (!c->path)
			die("out of memory");
	}
	memcpy(c->path, filesdir, filesdirlen);
	memcpy(c->path + filesdirlen, name, nl);
	c->path[filesdirlen + nl] = '\0';
	c->fbuf = malloc(FILEMAX);
	if (!c->fbuf)
		die("out of memory");
	c->fleft = 3;
	c->openres = c->readres = 0;
	s = sqe_get(3);
	io_uring_prep_openat_direct(s, AT_FDCWD, c->path, O_RDONLY, 0,
	                            (unsigned)c->id);
	s->flags |= IOSQE_IO_LINK;
	sqe_tag(s, c, T_FOPEN);
	s = sqe_get(1);
	io_uring_prep_read(s, c->id, c->fbuf, FILEMAX, 0);
	s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_HARDLINK;
	sqe_tag(s, c, T_FREAD);
	s = sqe_get(1);
	io_uring_prep_close_direct(s, (unsigned)c->id);
	sqe_tag(s, c, T_FCLOSE);
}

static void
up_send(Conn *c)
{
	struct io_uring_sqe *s;

	c->uplen = c->uphend = 0;
	c->upstate = UP_WAIT;
	s = sqe_get(1);
	io_uring_prep_send(s, c->upfd, c->upreq, c->upreqlen, MSG_NOSIGNAL);
	sqe_tag(s, c, T_UPSEND);
}

static void
do_proxy(Conn *c, uint32_t id)
{
	struct io_uring_sqe *s;
	int fd;

	c->upreqlen = upstream_request(c->upreq, id);
	if (c->upfd >= 0) {
		up_send(c);
		return;
	}
	if (!c->upbuf) {
		c->upbuf = malloc(UPBUF);
		if (!c->upbuf)
			die("out of memory");
	}
	fd = socket(backend.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		conn_kill(c);
		return;
	}
	nodelay(fd);
	c->upfd = fd;
	s = sqe_get(1);
	io_uring_prep_connect(s, fd, (struct sockaddr *)&backend, backendlen);
	sqe_tag(s, c, T_UPCONN);
}

static void
on_upconn(Conn *c, int res)
{
	c->inflight--;
	if (c->dead)
		return;
	if (res < 0) {
		conn_kill(c);
		return;
	}
	arm_recv(c, c->upfd, T_UPRECV);
	up_send(c);
}

static void
on_upsend(Conn *c, int res)
{
	c->inflight--;
	if (!c->dead && res != (int)c->upreqlen)
		conn_kill(c);
}

static void
on_uprecv(Conn *c, struct io_uring_cqe *cqe)
{
	const char *ct;
	size_t ctlen, from;

	from = c->uplen;
	/* Bytes while no request is out are a protocol error. */
	recv_take(c, cqe, c->upstate == UP_WAIT ? c->upbuf : NULL,
	          &c->uplen, UPBUF);
	if (recv_continue(c, cqe))
		arm_recv(c, c->upfd, T_UPRECV);
	if (c->dead || cqe->res <= 0)
		return;
	if (!c->uphend) {
		c->uphend = http_head_end(c->upbuf, c->uplen, from);
		if (!c->uphend) {
			if (c->uplen >= REQMAX)
				conn_kill(c);
			return;
		}
		if (!http_parse_resp(c->upbuf, c->uphend, &ct, &ctlen,
		                     &c->upclen)) {
			conn_kill(c);
			return;
		}
		c->uphl = http_head200(c->wbuf, ct, ctlen, c->upclen);
	}
	if (c->uplen < c->uphend + c->upclen)
		return;
	if (c->uplen > c->uphend + c->upclen) {
		conn_kill(c);
		return;
	}
	c->upstate = UP_IDLE;
	respond2(c, c->uphl, c->upbuf + c->uphend, c->upclen);
}

static void
wal_push(Conn *c)
{
	size_t n, cap;

	n = c->reqlen - c->hend;
	if (wal[walfill].len + n > wal[walfill].cap) {
		cap = wal[walfill].cap ? wal[walfill].cap : 1 << 16;
		while (cap < wal[walfill].len + n)
			cap *= 2;
		wal[walfill].buf = xrealloc(wal[walfill].buf, cap);
		wal[walfill].cap = cap;
	}
	memcpy(wal[walfill].buf + wal[walfill].len, c->rbuf + c->hend, n);
	wal[walfill].len += n;
	if (wal[walfill].n == wal[walfill].qcap) {
		wal[walfill].qcap = wal[walfill].qcap ? wal[walfill].qcap * 2
		                                      : 256;
		wal[walfill].q = xrealloc(wal[walfill].q,
		                          wal[walfill].qcap * sizeof(Conn *));
	}
	wal[walfill].q[wal[walfill].n++] = c;
	c->inflight++;
}

/* End of a turn: send the filled batch unless one is on the disk. */
static void
wal_kick(void)
{
	struct io_uring_sqe *s;
	int b;

	if (walbusy || !wal[walfill].n)
		return;
	b = walfill;
	walfill ^= 1;
	walbusy = 1;
	s = sqe_get(2);
	io_uring_prep_write(s, logfd, wal[b].buf, (unsigned)wal[b].len,
	                    (uint64_t)logoff);
	/* Success posts nothing; a failed or short write breaks the link. */
	s->flags |= IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS;
	sqe_tag(s, NULL, T_WALW);
	s = sqe_get(1);
	io_uring_prep_fsync(s, logfd, IORING_FSYNC_DATASYNC);
	sqe_tag(s, NULL, T_WALS);
	logoff += (off_t)wal[b].len;
}

static void
on_wal(int res)
{
	Conn *c;
	size_t i;
	int b;

	if (res < 0)
		die("wal fdatasync: %s", strerror(-res));
	b = walfill ^ 1;
	for (i = 0; i < wal[b].n; i++) {
		c = wal[b].q[i];
		c->inflight--;
		if (!c->dead)
			respond1(c, RESP_OK, sizeof(RESP_OK) - 1);
		conn_put(c);
	}
	wal[b].n = 0;
	wal[b].len = 0;
	walbusy = 0;
}

static void
on_event(void)
{
	Job *j, *next;
	Conn *c;

	arm_event();
	for (j = pool_take(); j; j = next) {
		next = j->next;
		c = j->owner;
		c->inflight--;
		if (!c->dead)
			respond1(c, c->wbuf, u64_response(c->wbuf, j->result));
		conn_put(c);
	}
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
			c->inflight++;
			pool_submit(&c->job);
			return;
		}
	} else if (r->method == M_POST && scen == S_WAL &&
	           r->pathlen == 4 && !memcmp(r->path, "/log", 4)) {
		wal_push(c);
		return;
	}
	respond404(c);
}

/* Start on the next complete request in rbuf, if any. */
static void
conn_serve(Conn *c)
{
	if (c->busy || c->dead)
		return;
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

static void
on_accept(struct io_uring_cqe *cqe)
{
	if (!(cqe->flags & IORING_CQE_F_MORE))
		arm_accept();
	if (cqe->res >= 0)
		conn_new(cqe->res);
}

static void
dispatch(struct io_uring_cqe *cqe)
{
	Conn *c;
	unsigned tag;

	tag = (unsigned)(cqe->user_data & TAGMASK);
	c = (Conn *)(uintptr_t)(cqe->user_data & ~TAGMASK);
	switch (tag) {
	case T_ACCEPT:
		on_accept(cqe);
		return;
	case T_EVENT:
		if (cqe->res < 0 && cqe->res != -EINTR && cqe->res != -EAGAIN)
			die("eventfd read: %s", strerror(-cqe->res));
		on_event();
		return;
	case T_WALW:
		die("wal write: %s", cqe->res < 0 ? strerror(-cqe->res)
		                                  : "short write");
		return;
	case T_WALS:
		on_wal(cqe->res);
		return;
	case T_RECV:
		on_recv(c, cqe);
		break;
	case T_SEND:
		on_send(c, cqe->res);
		break;
	case T_UPCONN:
		on_upconn(c, cqe->res);
		break;
	case T_UPSEND:
		on_upsend(c, cqe->res);
		break;
	case T_UPRECV:
		on_uprecv(c, cqe);
		break;
	case T_FOPEN:
	case T_FREAD:
	case T_FCLOSE:
		on_static(c, (int)tag, cqe->res);
		break;
	default:
		die("bad completion %llu", (unsigned long long)cqe->user_data);
	}
	conn_put(c);
}

static void
setup_ring(void)
{
	struct io_uring_params p;
	int rc, i;

	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN |
	          IORING_SETUP_SUBMIT_ALL | IORING_SETUP_CQSIZE;
	p.cq_entries = CQ_ENTRIES;
	rc = io_uring_queue_init_params(SQ_ENTRIES, &ring, &p);
	if (rc < 0)
		die("io_uring_queue_init: %s (needs Linux 6.1+)", strerror(-rc));
	io_uring_register_ring_fd(&ring);  /* an optimization only */

	br = io_uring_setup_buf_ring(&ring, NBUF, BGID, 0, &rc);
	if (!br)
		die("buffer ring: %s", strerror(-rc));
	if (posix_memalign((void **)&bufs, 4096, (size_t)NBUF * BUFSZ))
		die("out of memory");
	for (i = 0; i < NBUF; i++)
		io_uring_buf_ring_add(br, bufs + (size_t)i * BUFSZ, BUFSZ,
		                      (unsigned short)i,
		                      io_uring_buf_ring_mask(NBUF), i);
	io_uring_buf_ring_advance(br, NBUF);

	if (scen == S_STATIC) {
		rc = io_uring_register_files_sparse(&ring, (unsigned)nslots);
		if (rc < 0)
			die("register files: %s", strerror(-rc));
	}
}

int
main(int argc, char *argv[])
{
	struct io_uring_cqe *cqe;
	const char *s;
	char *d;
	unsigned head, n;
	long lim;
	int rc, i;

	if (argc != 3)
		die("usage: server SCENARIO PORT");
	scen = scenario(argv[1]);
	signal(SIGPIPE, SIG_IGN);
	lim = raise_nofile();
	/* Descriptors for the listener, ring, eventfd, log and upstreams. */
	nslots = (int)(lim / 2 > MAXCONN ? MAXCONN : lim / 2);
	if (nslots < 16)
		die("descriptor limit too low");
	conns = calloc((size_t)nslots, sizeof(*conns));
	freeids = malloc((size_t)nslots * sizeof(*freeids));
	if (!conns || !freeids)
		die("out of memory");
	for (i = 0; i < nslots; i++)
		freeids[i] = nslots - 1 - i;
	nfree = nslots;

	if (scen == S_STATIC) {
		s = getenv("FILES");
		if (!s)
			die("static needs FILES=dir");
		filesdirlen = strlen(s) + 1;
		d = malloc(filesdirlen);
		if (!d)
			die("out of memory");
		memcpy(d, s, filesdirlen - 1);
		d[filesdirlen - 1] = '/';
		filesdir = d;
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
	setup_ring();
	if (scen == S_CPU) {
		efd = pool_start(0);
		if (efd < 0)
			die("cpu pool: %m");
		arm_event();
	}
	lfd = listen_on(argv[2], 0);
	arm_accept();
	say_ready();

	for (;;) {
		rc = io_uring_submit_and_wait(&ring, 1);
		if (rc < 0 && rc != -EINTR && rc != -EBUSY && rc != -EAGAIN)
			die("io_uring_enter: %s", strerror(-rc));
		n = 0;
		io_uring_for_each_cqe(&ring, head, cqe) {
			dispatch(cqe);
			n++;
		}
		io_uring_cq_advance(&ring, n);
		wal_kick();
	}
}
