// Command ghfake serves the local GitHub stand-in on a port, for the smoke
// test and for trying the deployed stack without a real account or token.
// It is a test tool: nothing deployed imports it.
//
//	GHFAKE_TOKEN=any-string go run ./internal/gh/ghfake/cmd/ghfake \
//	  -addr 127.0.0.1:18090 -account octo -repos DIR
//
// DIR holds one directory per repository, as DIR/<owner>/<name>; each is
// served as a repository the account owns, with its files as the tarball.
// -base-url is the address clients use (it goes into Link headers), when
// that differs from -addr, as it does for a client inside a container.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/wanaware/vulnframework/internal/gh/ghfake"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18090", "listen address")
	base := flag.String("base-url", "", "address clients reach this server at; default http://ADDR")
	account := flag.String("account", "octo", "the account /user reports")
	reposDir := flag.String("repos", "", "directory of <owner>/<name> repositories to serve")
	flag.Parse()

	token := os.Getenv("GHFAKE_TOKEN")
	if token == "" {
		log.Fatal("GHFAKE_TOKEN must be set: the token clients must present")
	}
	var repos []ghfake.Repo
	if *reposDir != "" {
		owners, err := os.ReadDir(*reposDir)
		if err != nil {
			log.Fatal(err)
		}
		for _, o := range owners {
			if !o.IsDir() {
				continue
			}
			names, err := os.ReadDir(filepath.Join(*reposDir, o.Name()))
			if err != nil {
				log.Fatal(err)
			}
			for _, n := range names {
				if n.IsDir() {
					repos = append(repos, ghfake.Repo{
						FullName: o.Name() + "/" + n.Name(), SizeKB: 64,
						Dir: filepath.Join(*reposDir, o.Name(), n.Name()),
					})
				}
			}
		}
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].FullName < repos[j].FullName })

	s := &ghfake.Server{Account: *account, Token: token, Repos: repos, PageSize: 100, BaseURL: *base}
	if s.BaseURL == "" {
		s.BaseURL = "http://" + *addr
	}
	fmt.Fprintf(os.Stderr, "ghfake: %s serving %d repositories for %s at %s\n", *addr, len(repos), *account, s.BaseURL)
	log.Fatal(http.ListenAndServe(*addr, s))
}
