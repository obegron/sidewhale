package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var traceReqID uint64

func traceHTTPEnabled() bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv("SIDEWHALE_TRACE_HTTP")))
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}

type countingReadCloser struct {
	rc    io.ReadCloser
	count int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.count += int64(n)
	}
	return n, err
}

func (c *countingReadCloser) Close() error {
	if c.rc == nil {
		return nil
	}
	return c.rc.Close()
}

type traceResponseWriter struct {
	http.ResponseWriter
	status      int
	bytesWritten int64
}

func (w *traceResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *traceResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	if n > 0 {
		w.bytesWritten += int64(n)
	}
	return n, err
}

func traceHTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := atomic.AddUint64(&traceReqID, 1)
		start := time.Now()

		body := &countingReadCloser{rc: r.Body}
		r.Body = body

		tw := &traceResponseWriter{ResponseWriter: w}
		cl := r.Header.Get("Content-Length")
		if cl == "" {
			cl = strconv.FormatInt(r.ContentLength, 10)
		}
		fmt.Printf(
			"sidewhale: trace req id=%d event=start method=%s path=%s raw_query=%q remote=%s content_length=%s transfer_encoding=%v\n",
			id, r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr, cl, r.TransferEncoding,
		)

		next.ServeHTTP(tw, r)

		status := tw.status
		if status == 0 {
			status = http.StatusOK
		}
		fmt.Printf(
			"sidewhale: trace req id=%d event=end method=%s path=%s status=%d in_bytes=%d out_bytes=%d duration_ms=%d ctx_err=%q\n",
			id, r.Method, r.URL.Path, status, body.count, tw.bytesWritten, time.Since(start).Milliseconds(), errString(r.Context().Err()),
		)
	})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

