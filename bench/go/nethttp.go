package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// serveNetHTTP serves json or static through net/http with its defaults:
// the reference for what an ordinary Go service does.
func serveNetHTTP(ln net.Listener, name string) {
	mux := http.NewServeMux()
	switch name {
	case "json":
		mux.HandleFunc("GET /user/{id}", httpUser)
	case "static":
		files := mustEnv("FILES")
		mux.HandleFunc("GET /file/{name}", func(w http.ResponseWriter,
			r *http.Request) {
			httpFile(w, r, files)
		})
	default:
		fatal("unknown scenario: nethttp-" + name)
	}
	mux.HandleFunc("/", httpNotFound)
	ready()
	if err := http.Serve(ln, mux); err != nil {
		fatal("serve: " + err.Error())
	}
}

func httpNotFound(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h["Content-Type"] = []string{"text/plain"}
	h["Content-Length"] = []string{"0"}
	w.WriteHeader(http.StatusNotFound)
}

func httpUser(w http.ResponseWriter, r *http.Request) {
	id, ok := parseU32([]byte(r.PathValue("id")))
	if !ok {
		httpNotFound(w, r)
		return
	}
	body := appendUser(make([]byte, 0, userLen(10)), id)
	h := w.Header()
	h["Content-Type"] = []string{"application/json"}
	h["Content-Length"] = []string{strconv.Itoa(len(body))}
	w.Write(body)
}

func httpFile(w http.ResponseWriter, r *http.Request, dir string) {
	name := r.PathValue("name")
	if !validName([]byte(name)) || strings.ContainsRune(name, '/') {
		httpNotFound(w, r)
		return
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil || len(data) > maxFile {
		httpNotFound(w, r)
		return
	}
	h := w.Header()
	h["Content-Type"] = []string{"application/octet-stream"}
	h["Content-Length"] = []string{strconv.Itoa(len(data))}
	w.Write(data)
}
