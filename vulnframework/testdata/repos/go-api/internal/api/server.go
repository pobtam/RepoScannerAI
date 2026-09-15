package api

import (
	"net/http"

	"golang.org/x/net/http2"
)

// Serve starts the HTTP server. It configures HTTP/2 explicitly so the
// golang.org/x/net/http2 symbols are reachable from repository code.
func Serve() {
	srv := &http.Server{Addr: ":8080"}
	_ = http2.ConfigureServer(srv, &http2.Server{})
	_ = srv.ListenAndServe()
}
