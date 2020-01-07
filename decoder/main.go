package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"os"

	"github.com/masahide/mysql-audit-proxy/pkg/mysql"
)

const (
	maxPayloadLen int = 1<<24 - 1
)

type conbuf struct {
	in       *bytes.Buffer
	readSize int64
	sequence uint8
}

func main() {
	flag.Parse()
	args := flag.Args()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var in io.ReadCloser
	var err error
	switch {
	case len(args) == 0:
		in = os.Stdin
	default:
		in, err = os.Open(args[0])
		if err != nil {
			log.Fatal(err)
		}
	}
	if err := mysql.Decode(os.Stdout, in); err != nil {
		log.Fatal(err)
	}
}
