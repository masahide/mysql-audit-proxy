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

	"github.com/masahide/mysql-audit-proxy/pkg/gencode"
)

const (
	testDataFile1 = "test/testinputdata1.json"
	testDataFile2 = "test/testinputdata2.json"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestLogWorker(t *testing.T) {
	tests := []struct {
		name         string
		encType      byte
		testDataFile string
		result       bool
	}{
		{
			name: "gob1", encType: EncodeTypeGOB,
			testDataFile: testDataFile1,
			result:       true,
		},
		{
			name:         "colfer1",
			encType:      EncodeTypeColfer,
			testDataFile: testDataFile1,
			result:       true,
		},
		{
			name:         "gencode1",
			encType:      EncodeTypeGencode,
			testDataFile: testDataFile1,
			result:       true,
		},
		{
			name:         "gob2",
			encType:      EncodeTypeGOB,
			testDataFile: testDataFile2,
			result:       true,
		},
		{
			name:         "colfer2",
			encType:      EncodeTypeColfer,
			testDataFile: testDataFile2,
			result:       true,
		},
		{
			name:         "gencode2",
			encType:      EncodeTypeGencode,
			testDataFile: testDataFile2,
			result:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogWorker(t, tt.encType, tt.testDataFile, tt.result)
		})
	}
}

// Run server main process
func testLogWorker(t *testing.T, encType byte, testDataFile string, result bool) {
	tmpFile, _ := ioutil.TempFile("", "tmptest")
	defer os.Remove(tmpFile.Name() + ".gz")

	bufSize := 32 * 1024 * 1024
	bs := newBuffers(bufSize, 200)
	queue := make(chan *spBuffer, 1)
	al := &auditLogs{
		FileName:   tmpFile.Name(),
		RotateTime: time.Hour,
		Queue:      queue,
		EncodeType: encType,
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
		sp := &ColferSendPackets{}
		err := dec.Decode(sp)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		queue <- newSpBuffer(bs, sp)
	}
	cancel()
	close(queue)
	if err := <-logErrCh; err != nil {
		t.Fatalf("logWorker err:%s", err)
	}
	f.Close()
	diff := cmpStructs(tmpFile.Name()+".gz", testDataFile, t)
	if diff != "" && result {
		t.Errorf(diff)
	}
	if diff == "" && !result {
		t.Errorf("!!No Errors")
	}
}

func cmpStructs(filename, testDataFile string, t *testing.T) string {

	in, _ := os.Open(filename)
	gzr, _ := gzip.NewReader(in)
	a := &auditLogs{JSON: false}
	dec := a.newLogDecoder(gzr)
	dataf, _ := os.Open(testDataFile)
	defer dataf.Close()
	orgDec := json.NewDecoder(dataf)
	i := 1
	for {
		sp := &gencode.SendPackets{}
		org := &ColferSendPackets{}
		dataerr := dec.Decode(sp)
		if dataerr == io.EOF {
			break
		}
		if dataerr != nil {
			return dataerr.Error()
		}
		err := orgDec.Decode(org)
		if err == io.EOF {
			log.Println("data read:EOF")
			break
		}
		if err != nil {
			t.Fatalf("org Decode err:%s", err)
		}
		//pp.Println(i, org, sp)
		if diff := spcmp(org, sp); diff != "" {
			return fmt.Sprintf("%v mismatch (-want +got):\n%s", i, diff)
		}
		i++
	}
	return ""
}

func spcmp(a *ColferSendPackets, b *gencode.SendPackets) string {
	res := ""
	if a.Datetime.Unix() != b.Datetime {
		res = fmt.Sprintf("Datetime %v : %v\n", a.Datetime, b.Datetime)
	}
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
		res = fmt.Sprintf("State [%v] != [%v]\n", a.State, b.State)
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

func TestEncode(t *testing.T) {
	//b := []byte{}

	buf := &bytes.Buffer{}
	w := newBinaryWriter(buf, EncodeTypeColfer)
	packet := &ColferSendPackets{
		ConnectionID: 1,
		User:         "user01",
	}
	//packet.User = strings.Repeat("a", 1000000)
	if err := w.Encode(packet); err != nil {
		t.Error(err)
	}
	//pp.Println(buf.Bytes())
	buf.Reset()
	packet = &ColferSendPackets{}
	//packet.User = strings.Repeat("a", 1000000)
	if err := w.Encode(packet); err != nil {
		t.Error(err)
	}
	firstByte := buf.Bytes()[0]
	if firstByte != byte(1) {
		t.Errorf("first byte is not 1. first byte:%v", firstByte)
	}
}

func newSpBuffer(bs *buffers, org *ColferSendPackets) *spBuffer {
	sp := bs.Get()
	sp.Datetime = org.Datetime.Unix()
	sp.User = org.User
	sp.Db = org.Db
	sp.Addr = org.Addr
	sp.ConnectionID = org.ConnectionID
	sp.State = org.State
	sp.Packets = org.Packets
	return sp
}
