package mysql

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/k0kubun/pp"
)

const (
	testDataFile = "test/testinputdata.json"
)

func newSp(bs *buffers, org *SendPackets) *SendPackets {
	sp := bs.Get()
	sp.Datetime = org.Datetime
	sp.User = org.User
	sp.Db = org.Db
	sp.Addr = org.Addr
	sp.ConnectionID = org.ConnectionID
	sp.State = org.State
	sp.Packets = org.Packets
	return sp
}

// Run server main process
func TestLogWorker(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	tmpFile, _ := ioutil.TempFile("", "tmptest")
	defer os.Remove(tmpFile.Name() + ".gz")

	bufSize := 32 * 1024 * 1024
	bs := newBuffers(bufSize, 200)
	queue := make(chan *SendPackets, 200)
	al := &auditLogs{
		FileName:   tmpFile.Name(),
		RotateTime: time.Hour,
		Queue:      queue,
		Bs:         bs,
		Gzip:       true,
		MaxBufSize: bufSize,
	}
	ctx, cancel := context.WithCancel(context.Background())
	logErrCh := make(chan error, 1)
	go al.logWorker(ctx, logErrCh)
	f, err := os.Open(testDataFile)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(f)
	for {
		sp := &SendPackets{}
		err := dec.Decode(sp)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		queue <- newSp(bs, sp)
		if err == io.EOF {
			break
		}
	}
	cancel()
	close(queue)
	if err := <-logErrCh; err != nil {
		t.Errorf("logWorker err:%s", err)
	}
	f.Close()
	cmpStructs(tmpFile.Name()+".gz", t)
}

func cmpStructs(filename string, t *testing.T) {

	in, _ := os.Open(filename)
	gzr, _ := gzip.NewReader(in)
	a := &auditLogs{JSON: false}
	dec := a.newDecoder(gzr)
	dataf, _ := os.Open(testDataFile)
	defer dataf.Close()
	orgDec := json.NewDecoder(dataf)
	for {
		sp := &SendPackets{}
		org := &SendPackets{}
		dataerr := dec.Decode(sp)
		if dataerr == io.EOF {
			break
		}
		if dataerr != nil {
			t.Error(dataerr)
			return
		}
		err := orgDec.Decode(org)
		if err != nil {
			t.Fatalf("org Decode err:%s", err)
			return
		}
		pp.Println(org, sp)
		if diff := spcmp(org, sp); diff != "" {
			t.Errorf("MakeGatewayInfo() mismatch (-want +got):\n%s", diff)
		}
	}
}

func spcmp(a, b *SendPackets) string {
	res := ""
	if a.ConnectionID != b.ConnectionID {
		res = fmt.Sprintf("ConnectionID %v : %v\n", a.ConnectionID, b.ConnectionID)
	}
	if a.User != b.User {
		res = fmt.Sprintf("User %v : %v\n", a.User, b.User)
	}
	if a.Db != b.Db {
		res = fmt.Sprintf("Db %v : %v\n", a.Db, b.Db)
	}
	if a.Addr != b.Addr {
		res = fmt.Sprintf("Addr %v : %v\n", a.Addr, b.Addr)
	}
	if a.State != b.State {
		res = fmt.Sprintf("State %v : %v\n", a.State, b.State)
	}
	if a.Err != b.Err {
		res = fmt.Sprintf("Err %v : %v\n", a.Err, b.Err)
	}
	if bytes.Compare(a.Packets, b.Packets) != 0 {
		res = fmt.Sprintf("Packets %v : %v\n", a.Packets, b.Packets)
	}
	if a.Cmd != b.Cmd {
		res = fmt.Sprintf("Cmd %v : %v\n", a.Cmd, b.Cmd)
	}
	return res
}

func decode(filename string, t *testing.T) {
	in, _ := os.Open(filename)
	gzr, _ := gzip.NewReader(in)
	l := &LogDecoder{JSON: false}
	err := l.Decode(io.Discard, gzr)
	defer gzr.Close()
	in.Seek(0, 0)
	if err != nil {
		t.Error(err)
	}
	l.Decode(os.Stdout, gzr)
}
