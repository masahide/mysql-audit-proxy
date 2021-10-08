package mysql

import (
	"bytes"
	"testing"
)

func TestEncode(t *testing.T) {
	//b := []byte{}

	buf := &bytes.Buffer{}
	w := newBinaryWriter(buf)
	packet := &SendPackets{
		ConnectionID: 1,
		User:         "user01",
	}
	//packet.User = strings.Repeat("a", 1000000)
	if err := w.Encode(packet); err != nil {
		t.Error(err)
	}
	//pp.Println(buf.Bytes())
	buf.Reset()
	packet = &SendPackets{}
	//packet.User = strings.Repeat("a", 1000000)
	if err := w.Encode(packet); err != nil {
		t.Error(err)
	}
	firstByte := buf.Bytes()[0]
	if firstByte != byte(1) {
		t.Errorf("first byte is not 1. first byte:%v", firstByte)
	}
}
