// Command server is the Go entry of the cross-stack bench (see ../SPEC.md).
//
// Model: one goroutine per connection on a net.Listener, a bufio.Reader for
// input, one Write (or writev via net.Buffers) per response. Blocking work
// stays in the connection's goroutine because that is Go's model: the
// runtime parks it in the netpoller or hands its P off during a syscall,
// and preempts a long CPU loop (cpu /hash) so other goroutines still run.
// The wal scenario funnels appends to one writer goroutine that batches
// whatever is queued and syncs once per batch. Correct at any GOMAXPROCS.
//
// Scenario names starting with "nethttp-" (nethttp-json, nethttp-static)
// run the same handlers on net/http instead, as the real-world default.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	maxHead  = 8 << 10
	maxBody  = 64 << 10
	maxFile  = 1 << 20
	readBuf  = 16 << 10
	backlog  = 4096
	fnvBasis = 14695981039346656037
	fnvPrime = 1099511628211
)

var (
	crlf2    = []byte("\r\n\r\n")
	errHead  = errors.New("bad request head")
	errUp    = errors.New("bad upstream response")
	bio      = bytes.Repeat([]byte{'a'}, 900)
	zeroes   = make([]byte, 64<<10)
	notFound = []byte("HTTP/1.1 404 Not Found\r\n" +
		"Content-Type: text/plain\r\nContent-Length: 0\r\n\r\n")
	okBody = []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\nContent-Length: 2\r\n\r\nok")
)

type scenario int

const (
	scJSON scenario = iota
	scStatic
	scProxy
	scWAL
	scCPU
)

type config struct {
	sc      scenario
	files   string
	backend string
	wal     chan walReq
}

type conn struct {
	cfg  *config
	c    net.Conn
	r    *bufio.Reader
	out  []byte
	body []byte // for bodies larger than the read buffer
	up   net.Conn
	upr  *bufio.Reader
	done chan struct{}
}

type walReq struct {
	data []byte
	done chan struct{}
}

func main() {
	if len(os.Args) != 3 {
		os.Stderr.WriteString("usage: server SCENARIO PORT\n")
		os.Exit(2)
	}
	name, port := os.Args[1], os.Args[2]
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		fatal("bad port: " + port)
	}
	ln, err := listen(int(p))
	if err != nil {
		fatal("listen: " + err.Error())
	}
	if strings.HasPrefix(name, "nethttp-") {
		serveNetHTTP(ln, strings.TrimPrefix(name, "nethttp-"))
		return
	}
	cfg := &config{}
	switch name {
	case "json":
		cfg.sc = scJSON
	case "static":
		cfg.sc = scStatic
		cfg.files = mustEnv("FILES")
	case "proxy":
		cfg.sc = scProxy
		cfg.backend = mustEnv("BACKEND")
	case "wal":
		cfg.sc = scWAL
		cfg.wal = startWAL(mustEnv("LOG"))
	case "cpu":
		cfg.sc = scCPU
	default:
		fatal("unknown scenario: " + name)
	}
	ready()
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, syscall.EMFILE) ||
				errors.Is(err, syscall.ENFILE) ||
				errors.Is(err, syscall.ECONNABORTED) {
				continue
			}
			fatal("accept: " + err.Error())
		}
		go serve(cfg, c)
	}
}

func fatal(msg string) {
	os.Stderr.WriteString("server: " + msg + "\n")
	os.Exit(1)
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		fatal(k + " is not set")
	}
	return v
}

func ready() {
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		fatal("stdout: " + err.Error())
	}
}

// listen binds 0.0.0.0:port with SO_REUSEADDR and an explicit backlog,
// which net.Listen does not let one choose.
func listen(port int) (net.Listener, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET,
		syscall.SO_REUSEADDR, 1)
	if err == nil {
		err = syscall.Bind(fd, &syscall.SockaddrInet4{Port: port})
	}
	if err == nil {
		err = syscall.Listen(fd, backlog)
	}
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "listener")
	ln, err := net.FileListener(f)
	f.Close()
	return ln, err
}

func serve(cfg *config, c net.Conn) {
	k := &conn{
		cfg: cfg,
		c:   c,
		r:   bufio.NewReaderSize(c, readBuf),
		out: make([]byte, 0, 2048),
	}
	defer func() {
		c.Close()
		if k.up != nil {
			k.up.Close()
		}
	}()
	for {
		if err := k.one(); err != nil {
			return
		}
	}
}

// readHead returns the request (or response) head up to and including
// CRLFCRLF. The slice aliases r's buffer: it is valid until r is read or
// discarded again.
func readHead(r *bufio.Reader) ([]byte, error) {
	from := 0
	for {
		b, _ := r.Peek(r.Buffered())
		if i := bytes.Index(b[from:], crlf2); i >= 0 {
			return b[:from+i+4], nil
		}
		if len(b) >= maxHead {
			return nil, errHead
		}
		if len(b) > 3 {
			from = len(b) - 3
		}
		if _, err := r.Peek(len(b) + 1); err != nil {
			return nil, err
		}
	}
}

// header returns the value of header name (lowercase) in head, which
// starts with a request or status line.
func header(head []byte, name string) []byte {
	i := bytes.IndexByte(head, '\n')
	for i >= 0 && i+1 < len(head) {
		line := head[i+1:]
		j := bytes.IndexByte(line, '\n')
		if j < 0 {
			return nil
		}
		line = line[:j]
		i += j + 1
		if len(line) <= len(name) || line[len(name)] != ':' {
			continue
		}
		if !eqFold(line[:len(name)], name) {
			continue
		}
		return bytes.TrimSpace(line[len(name)+1:])
	}
	return nil
}

func eqFold(b []byte, lower string) bool {
	for i := 0; i < len(b); i++ {
		c := b[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

func parseU32(b []byte) (uint32, bool) {
	if len(b) == 0 || len(b) > 10 {
		return 0, false
	}
	var v uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
	}
	if v > 1<<32-1 {
		return 0, false
	}
	return uint32(v), true
}

// readBody returns n bytes of body following the head already discarded.
// A slice into r is valid until the next read; release with discard.
func readBody(r *bufio.Reader, n int, big *[]byte) ([]byte, bool, error) {
	if n <= r.Size() {
		b, err := r.Peek(n)
		return b, true, err
	}
	if cap(*big) < n {
		*big = make([]byte, n)
	}
	b := (*big)[:n]
	_, err := io.ReadFull(r, b)
	return b, false, err
}

func (k *conn) one() error {
	head, err := readHead(k.r)
	if err != nil {
		return err
	}
	sp := bytes.IndexByte(head, ' ')
	if sp < 0 {
		return errHead
	}
	method := head[:sp]
	rest := head[sp+1:]
	sp = bytes.IndexByte(rest, ' ')
	if sp < 0 {
		return errHead
	}
	path := rest[:sp]
	clen := 0
	if v := header(head, "content-length"); v != nil {
		n, ok := parseU32(v)
		if !ok || n > maxBody {
			return errHead
		}
		clen = int(n)
	}
	isGet := string(method) == "GET"
	isPost := string(method) == "POST"
	// The head slice dies here; copy what outlives the discard.
	var pathBuf [256]byte
	if len(path) > len(pathBuf) {
		path = nil
	} else {
		path = pathBuf[:copy(pathBuf[:], path)]
	}
	k.r.Discard(len(head))
	var body []byte
	inBuf := false
	if clen > 0 {
		body, inBuf, err = readBody(k.r, clen, &k.body)
		if err != nil {
			return err
		}
	}
	err = k.route(isGet, isPost, path, body)
	if inBuf {
		k.r.Discard(clen)
	}
	return err
}

func (k *conn) route(get, post bool, path, body []byte) error {
	cfg := k.cfg
	switch {
	case get && (cfg.sc == scJSON || cfg.sc == scCPU) &&
		bytes.HasPrefix(path, []byte("/user/")):
		id, ok := parseU32(path[6:])
		if ok {
			return k.json(id)
		}
	case get && cfg.sc == scCPU && bytes.HasPrefix(path, []byte("/hash/")):
		n, ok := parseU32(path[6:])
		if ok {
			return k.hash(n)
		}
	case get && cfg.sc == scStatic && bytes.HasPrefix(path, []byte("/file/")):
		return k.static(path[6:])
	case get && cfg.sc == scProxy && bytes.HasPrefix(path, []byte("/proxy/")):
		if _, ok := parseU32(path[7:]); ok {
			return k.proxy(path[7:])
		}
	case post && cfg.sc == scWAL && string(path) == "/log":
		return k.wal(body)
	}
	_, err := k.c.Write(notFound)
	return err
}

func appendHead(b []byte, ctype string, n int) []byte {
	b = append(b, "HTTP/1.1 200 OK\r\nContent-Type: "...)
	b = append(b, ctype...)
	b = append(b, "\r\nContent-Length: "...)
	b = strconv.AppendInt(b, int64(n), 10)
	return append(b, "\r\n\r\n"...)
}

func appendUser(b []byte, id uint32) []byte {
	var d [10]byte
	ds := strconv.AppendUint(d[:0], uint64(id), 10)
	b = append(b, `{"id":`...)
	b = append(b, ds...)
	b = append(b, `,"name":"user`...)
	b = append(b, ds...)
	b = append(b, `","email":"user`...)
	b = append(b, ds...)
	b = append(b, `@example.com","active":true,"roles":["reader","writer"],`+
		`"balance":1234.56,"bio":"`...)
	b = append(b, bio...)
	return append(b, `"}`...)
}

// userFixed is the json body length without the three ids.
var userFixed = len(appendUser(nil, 0)) - 3

// userLen is the length of the json body for an id of nd digits.
func userLen(nd int) int {
	return userFixed + 3*nd
}

func digits(v uint64) int {
	n := 1
	for v >= 10 {
		v /= 10
		n++
	}
	return n
}

func (k *conn) json(id uint32) error {
	b := appendHead(k.out[:0], "application/json", userLen(digits(uint64(id))))
	b = appendUser(b, id)
	k.out = b
	_, err := k.c.Write(b)
	return err
}

func fnv(n uint32) uint64 {
	h := uint64(fnvBasis)
	buf := zeroes
	for r := uint32(0); r < n; r++ {
		for _, c := range buf {
			h = (h ^ uint64(c)) * fnvPrime
		}
	}
	return h
}

func (k *conn) hash(n uint32) error {
	var d [20]byte
	ds := strconv.AppendUint(d[:0], fnv(n), 10)
	b := appendHead(k.out[:0], "text/plain", len(ds))
	b = append(b, ds...)
	k.out = b
	_, err := k.c.Write(b)
	return err
}

func validName(name []byte) bool {
	return len(name) > 0 && name[0] != '.' &&
		bytes.IndexByte(name, '/') < 0 && bytes.IndexByte(name, 0) < 0
}

func (k *conn) static(name []byte) error {
	if !validName(name) {
		_, err := k.c.Write(notFound)
		return err
	}
	data, err := readFile(filepath.Join(k.cfg.files, string(name)))
	if err != nil {
		_, err = k.c.Write(notFound)
		return err
	}
	k.out = appendHead(k.out[:0], "application/octet-stream", len(data))
	bufs := net.Buffers{k.out, data}
	_, err = bufs.WriteTo(k.c)
	return err
}

// readFile is os.ReadFile capped at maxFile.
func readFile(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	n := st.Size()
	if n > maxFile {
		n = maxFile
	}
	data := make([]byte, n)
	m, err := io.ReadFull(f, data)
	if err == io.ErrUnexpectedEOF {
		err = nil
	}
	return data[:m], err
}

func (k *conn) proxy(id []byte) error {
	if k.up == nil {
		up, err := net.Dial("tcp", k.cfg.backend)
		if err != nil {
			return err
		}
		k.up = up
		k.upr = bufio.NewReaderSize(up, readBuf)
	}
	req := append(k.out[:0], "GET /user/"...)
	req = append(req, id...)
	req = append(req, " HTTP/1.1\r\nHost: b\r\n\r\n"...)
	k.out = req
	if _, err := k.up.Write(req); err != nil {
		return err
	}
	head, err := readHead(k.upr)
	if err != nil {
		return err
	}
	if len(head) < 12 || string(head[:9]) != "HTTP/1.1 " {
		return errUp
	}
	n, ok := parseU32(header(head, "content-length"))
	if !ok || n > maxFile {
		return errUp
	}
	ct := header(head, "content-type")
	b := append(k.out[:0], "HTTP/1.1 200 OK\r\nContent-Type: "...)
	b = append(b, ct...)
	b = append(b, "\r\nContent-Length: "...)
	b = strconv.AppendUint(b, uint64(n), 10)
	b = append(b, "\r\n\r\n"...)
	k.upr.Discard(len(head))
	body, inBuf, err := readBody(k.upr, int(n), &k.body)
	if err != nil {
		return err
	}
	b = append(b, body...)
	if inBuf {
		k.upr.Discard(int(n))
	}
	k.out = b
	_, err = k.c.Write(b)
	return err
}

func (k *conn) wal(body []byte) error {
	if k.done == nil {
		k.done = make(chan struct{}, 1)
	}
	// body stays valid: this goroutine reads nothing until done.
	k.cfg.wal <- walReq{data: body, done: k.done}
	<-k.done
	_, err := k.c.Write(okBody)
	return err
}

// startWAL opens the log and starts the group-commit writer: it takes
// every request queued at the moment, writes them with one pwrite at the
// offset it keeps, syncs once, then releases them all.
func startWAL(path string) chan walReq {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fatal("open " + path + ": " + err.Error())
	}
	fd := int(f.Fd())
	ch := make(chan walReq, 8192)
	go func() {
		var off int64
		buf := make([]byte, 0, 1<<20)
		batch := make([]walReq, 0, 1024)
		for {
			batch = append(batch[:0], <-ch)
		drain:
			for {
				select {
				case q := <-ch:
					batch = append(batch, q)
				default:
					break drain
				}
			}
			buf = buf[:0]
			for _, q := range batch {
				buf = append(buf, q.data...)
			}
			if _, err := f.WriteAt(buf, off); err != nil {
				fatal("wal write: " + err.Error())
			}
			off += int64(len(buf))
			if err := datasync(f, fd); err != nil {
				fatal("wal sync: " + err.Error())
			}
			for _, q := range batch {
				q.done <- struct{}{}
			}
		}
	}()
	return ch
}
