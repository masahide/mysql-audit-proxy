package mysql

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/masahide/mysql-audit-proxy/pkg/colfer"
	"github.com/masahide/mysql-audit-proxy/pkg/gencode"
)

const (
	EncodeTypeColfer  = 0x00
	EncodeTypeGOB     = 0x01
	EncodeTypeGencode = 0x02

	DefaultEncodeType = EncodeTypeGencode

	defaultReadBufSize  = 1024
	defaultWriteBufSize = 1024
)

var decoderMap = map[byte]func(c *BinaryReader, s *gencode.SendPackets) error{
	EncodeTypeGOB:     gobReader,
	EncodeTypeGencode: gencodeReader,
}

var encoderMap = map[byte]func(c *BinaryWriter, s interface{}) error{
	EncodeTypeColfer:  colferEncode,
	EncodeTypeGOB:     gobEncode,
	EncodeTypeGencode: gencodeEncode,
}

// auditLogs audit log struct
type auditLogs struct {
	FileName   string
	Gzip       bool
	JSON       bool
	EncodeType byte
	RotateTime time.Duration
	Queue      chan *gencode.SendPackets
	Bs         *buffers

	gz io.WriteCloser
	f  *os.File
}

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

func (a *auditLogs) logWorker(ctx context.Context, res chan error) {
	var err error
	var w io.Writer
	defer func() { a.closeStream(); res <- err; close(res) }()
	if w, err = a.openStream(time.Now()); err != nil {
		return
	}
	e := a.newLogEncoder(w, a.EncodeType)
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
			e = a.newLogEncoder(w, a.EncodeType)
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

type logDecoder interface {
	Decode(interface{}) error
}

// LogDecoder struct
type LogDecoder struct {
	JSON       bool
	EncodeType byte
}

func writeErr(enc *json.Encoder, sp *gencode.SendPackets, err error) error {
	out := gencode.SendPackets{
		Datetime:     sp.Datetime,
		ConnectionID: sp.ConnectionID,
		User:         sp.User,
		Db:           sp.Db,
		Addr:         sp.Addr,
		State:        sp.State,
		Cmd:          string(sp.Packets),
		Err:          err.Error(),
	}
	return enc.Encode(out)
}

// Decode stream
func (l *LogDecoder) Decode(out io.Writer, in io.Reader) error {
	a := &auditLogs{
		JSON:       l.JSON,
		EncodeType: l.EncodeType,
	}
	dec := a.newLogDecoder(in)
	//dec := json.LogDecoder(in)
	jsonEnc := json.NewEncoder(out)
	for {
		sp := &gencode.SendPackets{}
		if err := dec.Decode(sp); err != nil {
			if err == io.EOF {
				break
			}
			return err
			/*
				if err := writeErr(jsonEnc, sp, err); err != nil {
					return err
				}
			*/
		}
		if sp.State != "est" {
			if err := jsonEnc.Encode(sp); err != nil {
				return err
			}
		}
		cb := &conbuf{
			in: bytes.NewBuffer(sp.Packets),
		}
		for {
			data, err := cb.readPacket()
			if err != nil {
				if err == io.EOF {
					break
				}
				/*
					if err := writeErr(jsonEnc, sp, err); err != nil {
						return err
					}
				*/
				return err
			}
			out := colfer.ColferSendPackets{
				Datetime:     time.Unix(sp.Datetime, 0),
				ConnectionID: sp.ConnectionID,
				User:         sp.User,
				Db:           sp.Db,
				Addr:         sp.Addr,
				State:        sp.State,
				Cmd:          cb.dispatch(data),
			}
			err = jsonEnc.Encode(out)
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
		}
	}
	return nil
}

func (a *auditLogs) newLogDecoder(r io.Reader) logDecoder {
	if !a.JSON {
		return a.newBinaryReader(r)
	}
	return json.NewDecoder(r)
}

type logEncoder interface {
	Encode(interface{}) error
}

func (a *auditLogs) newLogEncoder(w io.Writer, t byte) logEncoder {
	if !a.JSON {
		return a.newBinaryWriter(w, t)
	}
	return json.NewEncoder(w)
}
func (a *auditLogs) newBinaryWriter(w io.Writer, t byte) logEncoder {
	c := &BinaryWriter{
		output:     w,
		buf:        bytes.NewBuffer(make([]byte, defaultWriteBufSize)),
		encodeType: t,
	}
	return c
}

type BinaryWriter struct {
	output     io.Writer
	buf        *bytes.Buffer
	encodeType byte
}

// Encode SendPackets data
func (c *BinaryWriter) Encode(s interface{}) error {
	if e, ok := encoderMap[c.encodeType]; ok {
		return e(c, s)
	}
	return fmt.Errorf("not support encodetype:%x", c.encodeType)
}
func gencodeEncode(c *BinaryWriter, s interface{}) error {
	lengthBuf := make([]byte, binary.MaxVarintLen64)
	// header
	if _, err := c.output.Write([]byte{0, EncodeTypeGencode}); err != nil {
		return err
	}
	sp, ok := s.(*gencode.SendPackets)
	if !ok {
		switch v := s.(type) {
		default:
			return fmt.Errorf("not support data type:%T", v)
		}
	}
	spSize := int(sp.Size())
	c.buf.Reset()
	if c.buf.Cap() < spSize {
		c.buf.Grow(spSize)
	}
	buf := c.buf.Bytes()[:spSize]
	b, err := sp.Marshal(buf)
	if err != nil {
		return err
	}

	size := uint64(len(b))
	lenSize := binary.PutUvarint(lengthBuf, size)
	if _, err := c.output.Write(lengthBuf[:lenSize]); err != nil {
		return err
	}
	//log.Printf("data len:%d, buf len:%d, b len:%d", len(data), len(buf), len(b))
	_, err = c.output.Write(b)
	return err
}
func gobEncode(c *BinaryWriter, s interface{}) error {
	lengthBuf := make([]byte, binary.MaxVarintLen64)
	// header
	if _, err := c.output.Write([]byte{0, EncodeTypeGOB}); err != nil {
		return err
	}
	sp, ok := s.(*gencode.SendPackets)
	if !ok {
		switch v := s.(type) {
		default:
			return fmt.Errorf("not support data type:%T", v)
		}
	}
	c.buf.Reset()
	if err := gob.NewEncoder(c.buf).Encode(sp); err != nil {
		return err
	}
	size := uint64(c.buf.Len())
	lenSize := binary.PutUvarint(lengthBuf, size)
	if _, err := c.output.Write(lengthBuf[:lenSize]); err != nil {
		return err
	}
	_, err := io.Copy(c.output, c.buf)
	return err
}
func colferEncode(c *BinaryWriter, s interface{}) error {
	lengthBuf := make([]byte, binary.MaxVarintLen64)
	// header
	sp, ok := s.(*colfer.ColferSendPackets)
	if !ok {
		tsp, ok := s.(*gencode.SendPackets)
		if !ok {
			switch v := s.(type) {
			default:
				return fmt.Errorf("not support data type:%T", v)
			}
		}
		sp = getColferSp(tsp)
	}
	c.buf.Reset()
	if c.buf.Cap() < colfer.ColferSizeMax {
		c.buf.Grow(colfer.ColferSizeMax)
	}
	buf := c.buf.Bytes()[:colfer.ColferSizeMax]
	//log.Printf("buf size:%d,cap:%d ColferSizeMax:%d", len(buf), cap(buf), colfer.ColferSizeMax)
	size := sp.MarshalTo(buf)
	lenSize := binary.PutUvarint(lengthBuf, uint64(size))
	_, err := c.output.Write(lengthBuf[:lenSize])
	if err != nil {
		return err
	}
	_, err = c.output.Write(buf[:size])
	return err
}

type BinaryReader struct {
	input   *bufio.Reader
	readBuf *bytes.Buffer
}

func (a *auditLogs) newBinaryReader(r io.Reader) logDecoder {
	c := &BinaryReader{
		input:   bufio.NewReader(r),
		readBuf: bytes.NewBuffer(make([]byte, defaultReadBufSize)),
	}
	return c
}

func gencodeReader(c *BinaryReader, s *gencode.SendPackets) error {
	size, err := binary.ReadUvarint(c.input)
	if err != nil {
		return err
	}
	c.readBuf.Reset()
	if uint64(c.readBuf.Cap()) < size {
		c.readBuf.Grow(int(size))
	}
	readBuf := c.readBuf.Bytes()[:size]
	_, err = io.ReadFull(c.input, readBuf)
	if err != nil {
		return err
	}
	_, err = s.Unmarshal(readBuf)
	return err
}

func gobReader(c *BinaryReader, s *gencode.SendPackets) error {
	size, err := binary.ReadUvarint(c.input)
	if err != nil {
		return err
	}
	dec := gob.NewDecoder(io.LimitReader(c.input, int64(size)))
	if err != nil {
		return err
	}
	return dec.Decode(s)
}

func (c *BinaryReader) Decode(s interface{}) error {
	sp, ok := s.(*gencode.SendPackets)
	if !ok {
		return errors.New("not support data type")
	}
	b, err := c.input.ReadByte()
	if err == io.EOF {
		return err
	}
	if err != nil {
		return fmt.Errorf("not support data type: err read head:%v", err)
	}
	if b != 0 { // 0以外はcolfer
		c.input.UnreadByte()
		return c.colferDecode(sp)
	}
	b, err = c.input.ReadByte()
	if err == io.EOF {
		return err
	}
	if err != nil {
		return fmt.Errorf("not support data type: err read head:%v", err)
	}
	if dec, ok := decoderMap[b]; ok {
		return dec(c, sp)
	}
	return fmt.Errorf("not support logEncode type: %x", b)
}

func (c *BinaryReader) colferDecode(s *gencode.SendPackets) error {
	size, err := binary.ReadUvarint(c.input)
	if err != nil {
		return err
	}
	c.readBuf.Reset()
	if uint64(c.readBuf.Cap()) < size {
		c.readBuf.Grow(int(size))
	}
	readBuf := c.readBuf.Bytes()[:size]
	_, err = io.ReadFull(c.input, readBuf)
	if err != nil {
		return err
	}
	csp := &colfer.ColferSendPackets{}
	_, err = csp.Unmarshal(readBuf)
	cpSp(s, csp)
	return err
}

func getColferSp(sp *gencode.SendPackets) *colfer.ColferSendPackets {
	return &colfer.ColferSendPackets{
		Datetime:     time.Unix(sp.Datetime, 0),
		ConnectionID: sp.ConnectionID,
		User:         sp.User,
		Db:           sp.Db,
		Addr:         sp.Addr,
		State:        sp.State,
		Err:          sp.Err,
		Packets:      sp.Packets,
		Cmd:          sp.Cmd,
	}
}

func cpSp(to *gencode.SendPackets, csp *colfer.ColferSendPackets) {
	to.Datetime = csp.Datetime.Unix()
	to.ConnectionID = csp.ConnectionID
	to.User = csp.User
	to.Db = csp.Db
	to.Addr = csp.Addr
	to.State = csp.State
	to.Err = csp.Err
	to.Packets = csp.Packets
	to.Cmd = csp.Cmd
}
