/*
 * load: an HTTP/1.1 load generator for the bench servers (SPEC.md).
 *
 *   load HOST:PORT CONNS SECONDS RATE MIX...
 *
 * CONNS keep-alive connections, one request at a time on each. RATE 0 is
 * a closed loop: a connection sends its next request when the last answer
 * came. RATE > 0 is an open loop of so many requests a second over all
 * connections: request k is due at k / RATE, waits for a free connection
 * if none is, and its latency counts from when it was due, so that a
 * server that stalls is not forgiven (no coordinated omission). MIX is
 * weight:METHOD:PATH[:bodybytes]; {i} in PATH is a counter. WARMUP (env,
 * seconds, default 2) runs before the measured SECONDS. One JSON line on
 * stdout.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MIXMAX 8
#define INMAX (1 << 16)
#define FINE 100000 /* 1 us buckets up to 100 ms */
#define COARSE 4096 /* then 1 ms buckets up to ~4 s, then the last */

typedef struct {
	uint32_t fine[FINE];
	uint32_t coarse[COARSE];
	uint64_t count, max;
} Hist;

typedef struct {
	int weight;
	char method[8];
	char path[256];
	int body;
	Hist hist;
	uint64_t errors;
} Mix;

enum { IDLE, BUSY, DEAD };

typedef struct {
	int fd;
	int state;
	int mix;
	uint64_t due; /* ns the request was due (open) or sent (closed) */
	char out[1024 + 65536];
	size_t outlen, outoff;
	char in[INMAX];
	size_t inlen;
	int64_t body; /* body bytes still to come, -1 before the head */
} Conn;

static Mix mixes[MIXMAX];
static int nmix, wsum;
static Conn *conns;
static int nconns;
/* The connections free for a request (open loop), as a stack. */
static Conn **idle;
static int nidle;
static struct sockaddr_storage addr;
static socklen_t addrlen;
static int ep;
static uint64_t counter, measure_from, end_at;
static uint64_t requests, errors, connerrors;
static int measuring;

static uint64_t
now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

static void
die(const char *what)
{
	perror(what);
	exit(2);
}

static void
record(Hist *h, uint64_t ns)
{
	uint64_t us = ns / 1000;

	if (us < FINE)
		h->fine[us]++;
	else if ((us - FINE) / 1000 < COARSE - 1)
		h->coarse[(us - FINE) / 1000]++;
	else
		h->coarse[COARSE - 1]++;
	h->count++;
	if (us > h->max)
		h->max = us;
}

static uint64_t
percentile(const Hist *h, double p)
{
	uint64_t want, seen = 0;
	int i;

	if (!h->count)
		return 0;
	want = (uint64_t)(p * (double)h->count);
	if (want >= h->count)
		want = h->count - 1;
	for (i = 0; i < FINE; i++) {
		seen += h->fine[i];
		if (seen > want)
			return (uint64_t)i;
	}
	for (i = 0; i < COARSE; i++) {
		seen += h->coarse[i];
		if (seen > want)
			return FINE + (uint64_t)i * 1000;
	}
	return h->max;
}

static void
merge(Hist *into, const Hist *h)
{
	int i;

	for (i = 0; i < FINE; i++)
		into->fine[i] += h->fine[i];
	for (i = 0; i < COARSE; i++)
		into->coarse[i] += h->coarse[i];
	into->count += h->count;
	if (h->max > into->max)
		into->max = h->max;
}

static int
pick(void)
{
	static uint64_t turn;
	int r = (int)(turn++ % (uint64_t)wsum), i;

	for (i = 0; i < nmix; i++) {
		r -= mixes[i].weight;
		if (r < 0)
			return i;
	}
	return 0;
}

static void
build(Conn *c, int m)
{
	const Mix *x = &mixes[m];
	char path[300], num[24];
	const char *p, *at;
	size_t n = 0;
	int len;

	snprintf(num, sizeof(num), "%llu", (unsigned long long)(counter++ % 1000000));
	for (p = x->path; (at = strstr(p, "{i}")); p = at + 3) {
		memcpy(path + n, p, (size_t)(at - p));
		n += (size_t)(at - p);
		memcpy(path + n, num, strlen(num));
		n += strlen(num);
	}
	strcpy(path + n, p);
	if (x->body)
		len = snprintf(c->out, 1024, "%s %s HTTP/1.1\r\nHost: b\r\n"
		    "Content-Length: %d\r\n\r\n", x->method, path, x->body);
	else
		len = snprintf(c->out, 1024, "%s %s HTTP/1.1\r\nHost: b\r\n\r\n",
		    x->method, path);
	memset(c->out + len, 'x', (size_t)x->body);
	c->outlen = (size_t)len + (size_t)x->body;
	c->outoff = 0;
	c->mix = m;
	c->inlen = 0;
	c->body = -1;
}

static void
arm(Conn *c, uint32_t events)
{
	struct epoll_event e = { .events = events, .data.ptr = c };

	if (epoll_ctl(ep, EPOLL_CTL_MOD, c->fd, &e) < 0)
		die("epoll_ctl");
}

static void
dial(Conn *c)
{
	struct epoll_event e = { .events = EPOLLOUT, .data.ptr = c };
	int one = 1;

	c->fd = socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (c->fd < 0)
		die("socket");
	setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (connect(c->fd, (struct sockaddr *)&addr, addrlen) < 0 && errno != EINPROGRESS)
		die("connect");
	if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &e) < 0)
		die("epoll_ctl");
	c->state = DEAD; /* until it writes */
}

static void
lost(Conn *c)
{
	if (c->state == BUSY && measuring)
		mixes[c->mix].errors++;
	connerrors++;
	close(c->fd);
	dial(c);
}

static void
flush(Conn *c)
{
	ssize_t n;

	while (c->outoff < c->outlen) {
		n = send(c->fd, c->out + c->outoff, c->outlen - c->outoff, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EAGAIN) {
				arm(c, EPOLLIN | EPOLLOUT);
				return;
			}
			lost(c);
			return;
		}
		c->outoff += (size_t)n;
	}
	arm(c, EPOLLIN);
}

static void
start(Conn *c, uint64_t due)
{
	build(c, pick());
	c->state = BUSY;
	c->due = due;
	flush(c);
}

/* The head in c->in, once whole: its status and Content-Length, -1 when
 * it is not all there yet. */
static int
head(Conn *c, size_t *headlen, int64_t *length, int *status)
{
	char *end = memmem(c->in, c->inlen, "\r\n\r\n", 4), *p;

	if (!end)
		return -1;
	*headlen = (size_t)(end - c->in) + 4;
	*status = atoi(c->in + 9);
	*length = 0;
	for (p = c->in; p < end; p++) {
		if ((p == c->in || p[-1] == '\n') && !strncasecmp(p, "content-length:", 15)) {
			*length = strtoll(p + 15, NULL, 10);
			break;
		}
	}
	return 0;
}

static void done(Conn *c, int ok);

static void
readable(Conn *c)
{
	ssize_t n;
	size_t headlen;
	int64_t length;
	int status;

	for (;;) {
		n = recv(c->fd, c->in + c->inlen, INMAX - c->inlen, 0);
		if (n == 0 || (n < 0 && errno != EAGAIN)) {
			lost(c);
			return;
		}
		if (n < 0)
			return;
		if (c->body >= 0) {
			c->body -= n;
			if (c->body <= 0) {
				done(c, 1);
				return;
			}
			continue;
		}
		c->inlen += (size_t)n;
		if (head(c, &headlen, &length, &status) < 0) {
			if (c->inlen == INMAX) {
				lost(c);
				return;
			}
			continue;
		}
		c->body = length - (int64_t)(c->inlen - headlen);
		c->inlen = 0;
		if (c->body <= 0) {
			done(c, status == 200);
			return;
		}
		if (status != 200 && measuring)
			mixes[c->mix].errors++;
	}
}

/* Requests due and not yet started (open loop), as their due times. */
static uint64_t *waiting;
static size_t whead, wtail, wcap;
static uint64_t issued, t0, rate;

static void
done(Conn *c, int ok)
{
	uint64_t t = now();

	if (measuring && c->due >= measure_from) {
		if (ok) {
			record(&mixes[c->mix].hist, t - c->due);
			requests++;
		} else {
			mixes[c->mix].errors++;
		}
	}
	c->state = IDLE;
	if (!rate)
		start(c, t);
	else if (whead != wtail)
		start(c, waiting[whead++ % wcap]);
	else
		idle[nidle++] = c;
}

static void
schedule(uint64_t t)
{
	uint64_t due = (uint64_t)((double)(t - t0) * (double)rate / 1e9);
	for (; issued < due; issued++) {
		uint64_t at = t0 + (uint64_t)((double)issued * 1e9 / (double)rate);

		if (nidle && whead == wtail) {
			start(idle[--nidle], at);
		} else if (wtail - whead < wcap) {
			waiting[wtail++ % wcap] = at;
		} else {
			errors++; /* more due than the line holds */
		}
	}
}

static void
hist_json(const Hist *h)
{
	printf("{\"p50\":%llu,\"p90\":%llu,\"p99\":%llu,\"p999\":%llu,\"max\":%llu}",
	    (unsigned long long)percentile(h, .50), (unsigned long long)percentile(h, .90),
	    (unsigned long long)percentile(h, .99), (unsigned long long)percentile(h, .999),
	    (unsigned long long)h->max);
}

int
main(int argc, char **argv)
{
	struct epoll_event events[512];
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *found;
	char host[256], *colon;
	double seconds, warmup = 2;
	static Hist all;
	int i, n;

	if (argc < 6) {
		fprintf(stderr, "usage: load HOST:PORT CONNS SECONDS RATE MIX...\n");
		return 2;
	}
	signal(SIGPIPE, SIG_IGN);
	snprintf(host, sizeof(host), "%s", argv[1]);
	if (!(colon = strrchr(host, ':')))
		die("HOST:PORT");
	*colon = 0;
	if (getaddrinfo(host, colon + 1, &hints, &found))
		die("getaddrinfo");
	memcpy(&addr, found->ai_addr, found->ai_addrlen);
	addrlen = found->ai_addrlen;
	nconns = atoi(argv[2]);
	seconds = atof(argv[3]);
	rate = strtoull(argv[4], NULL, 10);
	if (getenv("WARMUP"))
		warmup = atof(getenv("WARMUP"));
	for (i = 5; i < argc && nmix < MIXMAX; i++) {
		Mix *m = &mixes[nmix++];

		if (sscanf(argv[i], "%d:%7[^:]:%255[^:]:%d", &m->weight, m->method,
		    m->path, &m->body) < 3)
			die("MIX");
		wsum += m->weight;
	}
	wcap = rate ? (size_t)rate * 10 + 1024 : 1;
	waiting = calloc(wcap, sizeof(*waiting));
	conns = calloc((size_t)nconns, sizeof(*conns));
	idle = calloc((size_t)nconns, sizeof(*idle));
	if (!waiting || !conns || !idle)
		die("calloc");
	if ((ep = epoll_create1(EPOLL_CLOEXEC)) < 0)
		die("epoll_create1");
	for (i = 0; i < nconns; i++)
		dial(&conns[i]);
	t0 = now();
	measure_from = t0 + (uint64_t)(warmup * 1e9);
	end_at = measure_from + (uint64_t)(seconds * 1e9);
	measuring = 1;
	for (;;) {
		uint64_t t = now();
		struct timespec wait = { 0, rate ? 100000 : 10000000 };

		if (t >= end_at)
			break;
		if (rate)
			schedule(t);
		n = epoll_pwait2(ep, events, 512, &wait, NULL);
		for (i = 0; i < n; i++) {
			Conn *c = events[i].data.ptr;

			if (c->state == DEAD) {
				int err = 0;
				socklen_t len = sizeof(err);

				getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &len);
				if (err) {
					connerrors++;
					close(c->fd);
					dial(c);
					continue;
				}
				c->state = IDLE;
				arm(c, EPOLLIN);
				if (!rate)
					start(c, now());
				else if (whead != wtail)
					start(c, waiting[whead++ % wcap]);
				else
					idle[nidle++] = c;
				continue;
			}
			if (events[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP))
				readable(c);
			if (c->state == BUSY && (events[i].events & EPOLLOUT) && c->outoff < c->outlen)
				flush(c);
		}
	}
	for (i = 0; i < nmix; i++) {
		merge(&all, &mixes[i].hist);
		errors += mixes[i].errors;
	}
	printf("{\"conns\":%d,\"rate\":%llu,\"seconds\":%g,\"requests\":%llu,"
	    "\"errors\":%llu,\"connerrors\":%llu,\"rps\":%.0f,\"lat\":",
	    nconns, (unsigned long long)rate, seconds, (unsigned long long)requests,
	    (unsigned long long)errors, (unsigned long long)connerrors,
	    (double)requests / seconds);
	hist_json(&all);
	printf(",\"mix\":[");
	for (i = 0; i < nmix; i++) {
		printf("%s{\"path\":\"%s\",\"requests\":%llu,\"errors\":%llu,\"lat\":",
		    i ? "," : "", mixes[i].path, (unsigned long long)mixes[i].hist.count,
		    (unsigned long long)mixes[i].errors);
		hist_json(&mixes[i].hist);
		printf("}");
	}
	printf("]}\n");
	return 0;
}
