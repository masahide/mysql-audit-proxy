package mysql

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// auditLogs audit log struct
type auditLogs struct {
	FileName   string
	Gzip       bool
	JSON       bool
	MaxBufSize int
	RotateTime time.Duration
	Queue      chan *SendPackets
	Bs         *buffers

	gz io.WriteCloser
	f  *os.File
}

/*
func truncate(t time.Time, d time.Duration) time.Time {
	if d == 24*time.Hour {
		return t.Truncate(time.Hour).Add(-time.Duration(t.Hour()) * time.Hour)
	}
	return t.Truncate(d)
}
*/

// /path/to/mysql-audit.%Y%m%d%H.log
func time2Path(p string, t time.Time) string {
	p = strings.Replace(p, "%Y", fmt.Sprintf("%04d", t.Year()), -1)
	p = strings.Replace(p, "%y", fmt.Sprintf("%02d", t.Year()%100), -1)
	p = strings.Replace(p, "%m", fmt.Sprintf("%02d", t.Month()), -1)
	p = strings.Replace(p, "%d", fmt.Sprintf("%02d", t.Day()), -1)
	p = strings.Replace(p, "%H", fmt.Sprintf("%02d", t.Hour()), -1)
	p = strings.Replace(p, "%M", fmt.Sprintf("%02d", t.Minute()), -1)
	p = strings.Replace(p, "%S", fmt.Sprintf("%02d", t.Second()), -1)
	return p
}

func (a *auditLogs) openStream(t time.Time) (f io.WriteCloser, err error) {
	name := time2Path(a.FileName, t)
	if a.Gzip {
		name = name + ".gz"
	}
	a.f, err = os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	if !a.Gzip {
		return a.f, nil
	}
	a.gz = gzip.NewWriter(a.f)
	return a.gz, nil
}
func (a *auditLogs) closeStream() (err error) {
	if a.gz != nil {
		err = a.gz.Close()
		if err != nil {
			return
		}
		a.gz = nil
	}
	if a.f == nil {
		return nil
	}
	err = a.f.Close()
	if err != nil {
		return err
	}
	a.f = nil
	return nil
}

type encoder interface {
	Encode(interface{}) error
}

func (a *auditLogs) newEncoder(w io.Writer) encoder {
	if !a.JSON {
		return newColferWriter(w)
	}
	return json.NewEncoder(w)
}

func (a *auditLogs) logWorker(ctx context.Context, res chan error) {
	var err error
	var w io.Writer
	ColferSizeMax = a.MaxBufSize << 1
	defer func() { a.closeStream(); res <- err; close(res) }()
	if w, err = a.openStream(time.Now()); err != nil {
		return
	}
	e := a.newEncoder(w)
	tt := time.NewTicker(a.RotateTime)
	defer tt.Stop()
	for {
		select {
		case t := <-tt.C:
			if err = a.closeStream(); err != nil {
				return
			}
			if w, err = a.openStream(t); err != nil {
				return
			}
			e = a.newEncoder(w)
		case <-ctx.Done():
			for p := range a.Queue {
				if err = e.Encode(p); err != nil {
					return
				}
				a.Bs.Put(p)
			}
			log.Println("Log flush completed.")
			return
		case p, ok := <-a.Queue:
			if !ok {
				return
			}
			if err = e.Encode(p); err != nil {
				return
			}
			a.Bs.Put(p)
		}
	}
}

type colferWriter struct {
	output  io.Writer
	dataBuf []byte
}

func newColferWriter(w io.Writer) *colferWriter {
	c := &colferWriter{
		output:  w,
		dataBuf: make([]byte, ColferSizeMax),
	}
	return c
}

// Encode SendPackets data
func (c *colferWriter) Encode(s interface{}) error {
	sp, ok := s.(*SendPackets)
	if !ok {
		return errors.New("not support data type")
	}
	size := uint64(sp.MarshalTo(c.dataBuf))
	lenSize := binary.PutUvarint(c.dataBuf[size:], size)
	_, err := c.output.Write(c.dataBuf[size : int(size)+lenSize])
	if err != nil {
		return err
	}
	_, err = c.output.Write(c.dataBuf[:size])
	return err
}

type colferReader struct {
	input   *bufio.Reader
	dataBuf []byte
}

type decoder interface {
	Decode(interface{}) error
}

func newColferReader(r io.Reader) *colferReader {
	c := &colferReader{
		input:   bufio.NewReader(r),
		dataBuf: make([]byte, ColferSizeMax),
	}
	return c
}

func (a *auditLogs) newDecoder(r io.Reader) decoder {
	if !a.JSON {
		return newColferReader(r)
	}
	return json.NewDecoder(r)
}
func (c *colferReader) Decode(s interface{}) error {
	sp, ok := s.(*SendPackets)
	if !ok {
		return errors.New("not support data type")
	}
	return c.decode(sp)
}
func (c *colferReader) decode(s *SendPackets) error {
	size, err := binary.ReadUvarint(c.input)
	if err != nil {
		return err
	}
	_, err = c.input.Read(c.dataBuf[:size])
	if err != nil {
		return err
	}
	_, err = s.Unmarshal(c.dataBuf[:size])
	return err
}

/*
func main() {
	x := uint64(12345678)
	b := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(b, x)
	fmt.Println(b[:n]) // -> [206 194 241 5]

	b = append(b[:n], []byte{3, 2, 2, 1, 2}...)

	fmt.Println(b) // -> [206 194 241 5]

	buf := bytes.NewReader(b)
	i, err := binary.ReadUvarint(buf)
	fmt.Printf("i=%d, err=%v\n", i, err)
	a := make([]byte, 100)
	size, err := buf.Read(a)
	fmt.Printf("buf.Read(a)-> size=%d, err=%v, a[:size]=[%# x]\n", size, err, a[:size])
}

*/
