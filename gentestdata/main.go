package main

import (
	"bytes"
	"flag"
	"os"
)

var (
	loop = 100
	size = 23 * 16
)

func main() {

	flag.IntVar(&loop, "l", loop, "loop count")
	flag.IntVar(&size, "s", size, "query text size")
	flag.Parse()

	for i := 0; i < loop; i++ {
		os.Stdout.Write([]byte("select CHAR_LENGTH(\""))
		//os.Stdout.Write(bytes.Repeat([]byte("a"), 23*16)) // 10 * 16 NG
		os.Stdout.Write(bytes.Repeat([]byte("a"), size)) // 10 * 15 OK
		os.Stdout.Write([]byte("\") as len;\n"))

	}
}
