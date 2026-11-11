// Command nuguardfake serves the local NuGuard stand-in on a port, for the
// deployed stack's test (deploy/test-stack.sh). It is a test tool: nothing
// deployed imports it.
//
//	NUGUARD_FAKE_KEY=any-string nuguardfake -addr 127.0.0.1:8085 \
//	  -script https://github.com/octo/go-api=ai-code.json \
//	  -script https://github.com/octo/payments-web=quickstart-partial.json
//
// Each -script serves a captured ScanResult for one repository URL; the
// job block is rewritten to describe the job actually submitted. A URL with
// no script is refused, as the real service refuses a host it does not allow.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/wanaware/vulnframework/internal/nuguard/nuguardfake"
)

type scripts []string

func (s *scripts) String() string     { return strings.Join(*s, ",") }
func (s *scripts) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	addr := flag.String("addr", "127.0.0.1:8085", "listen address")
	version := flag.String("version", "0.9.15", "the NuGuard version capabilities and results report")
	narrow := flag.Bool("narrow", false, "serve only the tools each submission asked for, as the service does")
	var sc scripts
	flag.Var(&sc, "script", "repo-url=result.json; repeatable")
	flag.Parse()

	key := os.Getenv("NUGUARD_FAKE_KEY")
	if key == "" {
		log.Fatal("NUGUARD_FAKE_KEY must be set: the API key clients must present")
	}
	fake := nuguardfake.NewHandler(key, *version)
	fake.Narrow = *narrow
	for _, s := range sc {
		url, file, ok := strings.Cut(s, "=")
		if !ok {
			log.Fatalf("-script %q: want repo-url=result.json", s)
		}
		b, err := os.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		fake.Script(url, &nuguardfake.Script{Result: b, Polls: 1})
	}
	log.Printf("fake NuGuard %s on %s with %d scripted repositories", *version, *addr, len(sc))
	log.Fatal(http.ListenAndServe(*addr, fake))
}
