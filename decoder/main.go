package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/masahide/mysql-audit-proxy/decoder/hack"
	"github.com/masahide/mysql-audit-proxy/pkg/mysql"
	flag "github.com/spf13/pflag"
)

const (
	maxPayloadLen int = 1<<24 - 1
)

type conbuf struct {
	in       *bytes.Buffer
	readSize int64
	sequence uint8
}

var (
	verbose  bool
	jsonFlag bool
)

func main() {
	flag.BoolVar(&jsonFlag, "json", jsonFlag, "json log file mode")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.Parse()
	args := flag.Args()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if len(args) == 0 {
		fmt.Println("Specify the file name in the argument.\nexample:")
		fmt.Printf("$ %s \"gzip filename\" > outputfile\n", os.Args[0])
		return
	}
	for _, filename := range args {
		if isZeroGz(filename) {
			continue
		}
		if verbose {
			log.Printf("filename:%s ...", filename)
		}
		decoder(filename)
	}

}
func isZeroGz(filename string) bool {
	in, err := os.Open(filename)
	if err != nil {
		log.Printf("fle: %s, err: %s", filename, err)
		return true
	}
	gzr, err := gzip.NewReader(in)
	if err != nil {
		log.Printf("fle: %s, err: %s", filename, err)
		return true
	}
	b := make([]byte, 10)
	n, _ := gzr.Read(b)
	gzr.Close()
	in.Close()
	return n == 0
}

func decoder(filename string) {
	in, err := os.Open(filename)
	if err != nil {
		log.Printf("fle: %s, err: %s", filename, err)
		return
	}
	gzr, err := gzip.NewReader(in)
	if err != nil {
		log.Printf("fle: %s, err: %s", filename, err)
		return
	}
	l := &mysql.LogDecoder{JSON: jsonFlag, EncodeType: mysql.DefaultEncodeType}
	err = l.Decode(io.Discard, gzr)
	gzr.Close()
	in.Seek(0, 0)
	if err != nil {
		log.Printf("err:%s", err)
		log.Printf("%s --- Log data corruption was found, so switch to forced parsing..", filename)
		gzr, err := gzip.NewReader(in)
		if err != nil {
			log.Printf("fle: %s, err: %s", filename, err)
		}
		hack.ForcedParse(gzr)
		return
	}
	gzr, err = gzip.NewReader(in)
	if err != nil {
		log.Printf("fle: %s, err: %s", filename, err)
	}
	if err := l.Decode(os.Stdout, gzr); err != nil {
		log.Printf("fle: %s, err: %s", filename, err)
	}
}
