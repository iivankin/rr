/*
 * Shared protocol code of the C bench servers (c-epoll, c-uring): request
 * parsing, the json template, response headers and the cpu hash. Header
 * only, so that each server stays one gcc line. See ../SPEC.md.
 */
#ifndef BENCH_HTTP_H
#define BENCH_HTTP_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define REQMAX   8192           /* request line + headers */
#define BODYMAX  65536          /* POST body */
#define FILEMAX  (1 << 20)      /* static file */
#define HASHBUF  65536          /* cpu: buffer the hash runs over */
#define HDRMAX   256            /* response header we build */
#define JSONMAX  2048           /* json body (about 1.1 KiB) */
#define CTMAX    128            /* proxied Content-Type value */

enum { M_OTHER, M_GET, M_POST };

typedef struct {
	int method;
	const char *path;
	size_t pathlen;
	size_t hdrlen;          /* bytes up to and including \r\n\r\n */
	size_t clen;            /* Content-Length, 0 when absent */
} Req;

static const char RESP_404[] =
	"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
static const char RESP_OK[] =
	"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
	"Content-Length: 2\r\n\r\nok";

/*
 * Find the end of the head: offset just past "\r\n\r\n", or 0 when it is
 * not there yet. from is where the previous scan stopped, so a request
 * that arrives in pieces is not scanned again from the start.
 */
static inline size_t
http_head_end(const char *b, size_t len, size_t from)
{
	const char *p, *e;

	from = from > 3 ? from - 3 : 0;
	p = b + from;
	e = b + len;
	while (e - p >= 4) {
		p = memchr(p, '\r', (size_t)(e - p) - 3);
		if (!p)
			return 0;
		if (p[1] == '\n' && p[2] == '\r' && p[3] == '\n')
			return (size_t)(p + 4 - b);
		p++;
	}
	return 0;
}

static inline int
lower(int c)
{
	return c >= 'A' && c <= 'Z' ? c + 32 : c;
}

/*
 * Find header name (lower case) among the header lines of b[0..hdrlen),
 * skipping the first line. Returns 1 and the value with surrounding
 * blanks trimmed, or 0.
 */
static inline int
http_header(const char *b, size_t hdrlen, const char *name,
            const char **val, size_t *vallen)
{
	const char *p, *e, *eol, *v, *ve;
	size_t nl, i;

	nl = strlen(name);
	e = b + hdrlen;
	p = memchr(b, '\n', hdrlen);
	if (!p)
		return 0;
	for (p++; p < e; p = eol + 1) {
		eol = memchr(p, '\n', (size_t)(e - p));
		if (!eol)
			return 0;
		if ((size_t)(eol - p) <= nl || p[nl] != ':')
			continue;
		for (i = 0; i < nl && lower((unsigned char)p[i]) == name[i]; i++)
			;
		if (i != nl)
			continue;
		v = p + nl + 1;
		ve = eol;
		while (v < ve && (*v == ' ' || *v == '\t'))
			v++;
		while (ve > v && (ve[-1] == '\r' || ve[-1] == ' ' ||
		       ve[-1] == '\t'))
			ve--;
		*val = v;
		*vallen = (size_t)(ve - v);
		return 1;
	}
	return 0;
}

/* Decimal of at most 10 digits that fits in u32. */
static inline int
parse_u32(const char *s, size_t n, uint32_t *out)
{
	uint64_t v;
	size_t i;

	if (n == 0 || n > 10)
		return 0;
	v = 0;
	for (i = 0; i < n; i++) {
		if (s[i] < '0' || s[i] > '9')
			return 0;
		v = v * 10 + (uint64_t)(s[i] - '0');
	}
	if (v > 0xffffffffu)
		return 0;
	*out = (uint32_t)v;
	return 1;
}

/* Writes the decimal of v at d (no NUL), returns its length (<= 20). */
static inline size_t
fmt_u64(char *d, uint64_t v)
{
	char t[20];
	size_t n, i;

	n = 0;
	do {
		t[n++] = (char)('0' + v % 10);
		v /= 10;
	} while (v);
	for (i = 0; i < n; i++)
		d[i] = t[n - 1 - i];
	return n;
}

/*
 * Parse the head b[0..hdrlen). Returns 0 on a malformed request (the
 * connection is then closed): no request line, or a Content-Length
 * that is not a number or is over BODYMAX.
 */
static inline int
http_parse(const char *b, size_t hdrlen, Req *r)
{
	const char *sp, *sp2, *eol, *v;
	size_t vl, i;
	uint64_t cl;

	eol = memchr(b, '\r', hdrlen);
	sp = memchr(b, ' ', (size_t)(eol - b));
	if (!sp)
		return 0;
	sp2 = memchr(sp + 1, ' ', (size_t)(eol - sp - 1));
	if (!sp2)
		return 0;
	if (sp - b == 3 && !memcmp(b, "GET", 3))
		r->method = M_GET;
	else if (sp - b == 4 && !memcmp(b, "POST", 4))
		r->method = M_POST;
	else
		r->method = M_OTHER;
	r->path = sp + 1;
	r->pathlen = (size_t)(sp2 - sp - 1);
	r->hdrlen = hdrlen;
	r->clen = 0;
	if (r->method != M_POST)
		return 1;
	if (!http_header(b, hdrlen, "content-length", &v, &vl))
		return 1;
	if (vl == 0 || vl > 7)
		return 0;
	cl = 0;
	for (i = 0; i < vl; i++) {
		if (v[i] < '0' || v[i] > '9')
			return 0;
		cl = cl * 10 + (uint64_t)(v[i] - '0');
	}
	if (cl > BODYMAX)
		return 0;
	r->clen = (size_t)cl;
	return 1;
}

/* If the path is prefix followed by something, set *rest to it. */
static inline int
path_arg(const Req *r, const char *prefix, size_t plen,
         const char **rest, size_t *restlen)
{
	if (r->pathlen <= plen || memcmp(r->path, prefix, plen))
		return 0;
	*rest = r->path + plen;
	*restlen = r->pathlen - plen;
	return 1;
}

/*
 * "HTTP/1.1 200 OK\r\nContent-Type: <ct>\r\nContent-Length: <n>\r\n\r\n"
 * into d (HDRMAX bytes; ct is at most CTMAX). Returns its length.
 */
static inline size_t
http_head200(char *d, const char *ct, size_t ctlen, size_t n)
{
	static const char a[] = "HTTP/1.1 200 OK\r\nContent-Type: ";
	static const char b[] = "\r\nContent-Length: ";
	char *p;

	p = d;
	memcpy(p, a, sizeof(a) - 1);
	p += sizeof(a) - 1;
	memcpy(p, ct, ctlen);
	p += ctlen;
	memcpy(p, b, sizeof(b) - 1);
	p += sizeof(b) - 1;
	p += fmt_u64(p, n);
	memcpy(p, "\r\n\r\n", 4);
	p += 4;
	return (size_t)(p - d);
}

#define CT_JSON  "application/json"
#define CT_TEXT  "text/plain"
#define CT_OCTET "application/octet-stream"

#define A10  "aaaaaaaaaa"
#define A100 A10 A10 A10 A10 A10 A10 A10 A10 A10 A10
#define A900 A100 A100 A100 A100 A100 A100 A100 A100 A100

static const char J1[] = "{\"id\":";
static const char J2[] = ",\"name\":\"user";
static const char J3[] = "\",\"email\":\"user";
static const char J4[] = "@example.com\",\"active\":true,"
	"\"roles\":[\"reader\",\"writer\"],\"balance\":1234.56,"
	"\"bio\":\"" A900 "\"}";

/*
 * The whole json response (head and body) for id into d, which must
 * hold HDRMAX + JSONMAX bytes. Returns its length.
 */
static inline size_t
json_response(char *d, uint32_t id)
{
	char ids[20];
	size_t il, bl, hl;
	char *p;

	il = fmt_u64(ids, id);
	bl = sizeof(J1) - 1 + sizeof(J2) - 1 + sizeof(J3) - 1 +
	     sizeof(J4) - 1 + 3 * il;
	hl = http_head200(d, CT_JSON, sizeof(CT_JSON) - 1, bl);
	p = d + hl;
	memcpy(p, J1, sizeof(J1) - 1);
	p += sizeof(J1) - 1;
	memcpy(p, ids, il);
	p += il;
	memcpy(p, J2, sizeof(J2) - 1);
	p += sizeof(J2) - 1;
	memcpy(p, ids, il);
	p += il;
	memcpy(p, J3, sizeof(J3) - 1);
	p += sizeof(J3) - 1;
	memcpy(p, ids, il);
	p += il;
	memcpy(p, J4, sizeof(J4) - 1);
	p += sizeof(J4) - 1;
	return (size_t)(p - d);
}

/* Text response with the decimal of v into d (HDRMAX + 20 bytes). */
static inline size_t
u64_response(char *d, uint64_t v)
{
	char t[20];
	size_t n, hl;

	n = fmt_u64(t, v);
	hl = http_head200(d, CT_TEXT, sizeof(CT_TEXT) - 1, n);
	memcpy(d + hl, t, n);
	return hl + n;
}

/*
 * The cpu work: n rounds of FNV-1a style mixing over buf (HASHBUF bytes
 * of zeroes). buf comes from the heap so that the compiler cannot fold
 * the loads.
 */
static inline uint64_t
fnv_rounds(const unsigned char *buf, uint32_t n)
{
	uint64_t h;
	uint32_t r;
	size_t i;

	h = 14695981039346656037ull;
	for (r = 0; r < n; r++)
		for (i = 0; i < HASHBUF; i++)
			h = (h ^ buf[i]) * 1099511628211ull;
	return h;
}

/*
 * Upstream response head: status line, Content-Type, Content-Length.
 * Returns 0 when malformed.
 */
static inline int
http_parse_resp(const char *b, size_t hdrlen, const char **ct,
                size_t *ctlen, size_t *clen)
{
	const char *v;
	size_t vl, i, cl;

	if (hdrlen < 12 || memcmp(b, "HTTP/1.", 7))
		return 0;
	if (!http_header(b, hdrlen, "content-length", &v, &vl) ||
	    vl == 0 || vl > 7)
		return 0;
	cl = 0;
	for (i = 0; i < vl; i++) {
		if (v[i] < '0' || v[i] > '9')
			return 0;
		cl = cl * 10 + (size_t)(v[i] - '0');
	}
	if (cl > BODYMAX)
		return 0;
	*clen = cl;
	if (!http_header(b, hdrlen, "content-type", ct, ctlen)) {
		*ct = CT_OCTET;
		*ctlen = sizeof(CT_OCTET) - 1;
	}
	if (*ctlen > CTMAX)
		return 0;
	return 1;
}

/* "GET /user/<id> HTTP/1.1\r\nHost: b\r\n\r\n" into d (64 bytes). */
static inline size_t
upstream_request(char *d, uint32_t id)
{
	static const char a[] = "GET /user/";
	static const char b[] = " HTTP/1.1\r\nHost: b\r\n\r\n";
	char *p;

	p = d;
	memcpy(p, a, sizeof(a) - 1);
	p += sizeof(a) - 1;
	p += fmt_u64(p, id);
	memcpy(p, b, sizeof(b) - 1);
	p += sizeof(b) - 1;
	return (size_t)(p - d);
}

/* A file name under $FILES: no '/', not starting with '.'. */
static inline int
file_name_ok(const char *s, size_t n)
{
	return n > 0 && n < 256 && s[0] != '.' && !memchr(s, '/', n) &&
	       !memchr(s, '\0', n);
}

#endif
