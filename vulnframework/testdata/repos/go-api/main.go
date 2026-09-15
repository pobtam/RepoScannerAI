// Command wanaware-api is a synthetic repository used to exercise the scanner
// adapters against real tool output (VM-AD §17 Phase 3).
//
// Every defect in this tree is deliberate.
package main

import (
	"fmt"

	"github.com/org/wanaware-api/internal/api"
	"github.com/org/wanaware-api/internal/sshgw"
)

func main() {
	fmt.Println("listening")
	go sshgw.Listen("127.0.0.1:2222")
	api.Serve()
}
