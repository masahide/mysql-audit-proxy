package mysql

import (
	"context"
	"net"
	"testing"
	"time"
)

type testAddr struct {
}

func (a *testAddr) Network() string { return "" }
func (a *testAddr) String() string  { return "" }

type testConn struct {
	buf []byte
}

func (c *testConn) Read(b []byte) (n int, err error) {
	return 0, nil
}
func (c *testConn) Write(b []byte) (n int, err error) {
	c.buf = make([]byte, len(b))
	size := copy(c.buf, b)
	return size, nil
}
func (c *testConn) Close() error                       { return nil }
func (c *testConn) LocalAddr() net.Addr                { return &testAddr{} }
func (c *testConn) RemoteAddr() net.Addr               { return &testAddr{} }
func (c *testConn) SetDeadline(t time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(t time.Time) error { return nil }

func TestNetWrite(t *testing.T) {
	cc := &ClientConn{}
	tconn := &testConn{}
	testBytes := []byte("hoge")
	size, err := cc.netWrite(context.Background(), tconn, testBytes)
	if err != nil {
		t.Error(err)
	}
	if size != len(testBytes) {
		t.Errorf("size:%v != len(testBytes):%v", size, len(testBytes))
	}
}
