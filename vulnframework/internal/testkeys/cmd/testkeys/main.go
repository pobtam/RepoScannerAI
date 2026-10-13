// Command testkeys rewrites fixture files between their committed form
// (placeholders) and their scanned form (fabricated values). It is a
// fixture tool for testdata/capture.sh, never part of a deployed program.
//
//	go run ./internal/testkeys/cmd/testkeys expand  DIR   # placeholders -> values
//	go run ./internal/testkeys/cmd/testkeys conceal DIR   # values -> placeholders
//
// Every regular file under DIR is rewritten in place; run expand only on a
// copy.
package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/wanaware/vulnframework/internal/testkeys"
)

func main() {
	if len(os.Args) != 3 || (os.Args[1] != "expand" && os.Args[1] != "conceal") {
		fmt.Fprintln(os.Stderr, "usage: testkeys expand|conceal DIR")
		os.Exit(2)
	}
	rewrite := testkeys.Expand
	if os.Args[1] == "conceal" {
		rewrite = testkeys.Conceal
	}
	changed := 0
	err := filepath.WalkDir(os.Args[2], func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out := rewrite(b)
		if bytes.Equal(out, b) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		changed++
		return os.WriteFile(path, out, info.Mode().Perm())
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "testkeys:", err)
		os.Exit(1)
	}
	fmt.Printf("testkeys %s: %d file(s) rewritten\n", os.Args[1], changed)
}
