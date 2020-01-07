package mysql

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/siddontang/mixer/hack"
	"github.com/siddontang/mixer/mysql"
)

const (
	maxPayloadLen int = 1<<24 - 1
)

type conbuf struct {
	in       *bytes.Buffer
	readSize int64
	sequence uint8
}

func writeErr(enc *json.Encoder, sp *SendPackets, err error) error {
	out := SendPackets{
		Datetime:     sp.Datetime,
		ConnectionID: sp.ConnectionID,
		User:         sp.User,
		Db:           sp.Db,
		Addr:         sp.Addr,
		State:        sp.State,
		Packets:      sp.Packets,
		Err:          err.Error(),
	}
	return enc.Encode(out)
}

// Decode stream
func Decode(out io.Writer, in io.Reader) error {
	dec := json.NewDecoder(in)
	enc := json.NewEncoder(out)
	for {
		sp := &SendPackets{}
		if err := dec.Decode(sp); err != nil {
			if err == io.EOF {
				break
			}
			if err := writeErr(enc, sp, err); err != nil {
				return err
			}
		}
		if sp.State != "est" {
			if err := enc.Encode(sp); err != nil {
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
				if err := writeErr(enc, sp, err); err != nil {
					return err
				}
			}
			out := SendPackets{
				Datetime:     sp.Datetime,
				ConnectionID: sp.ConnectionID,
				User:         sp.User,
				Db:           sp.Db,
				Addr:         sp.Addr,
				State:        sp.State,
				Cmd:          cb.dispatch(data),
			}
			err = enc.Encode(out)
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

func (c *conbuf) dispatch(data []byte) string {
	cmd := data[0]
	data = data[1:]

	switch cmd {
	case mysql.COM_QUIT:
		return "quit"
	case mysql.COM_QUERY:
		return hack.String(data)
	case mysql.COM_PING:
		return "ping"
	case mysql.COM_INIT_DB:
		return fmt.Sprintf("use %s", hack.String(data))
	case mysql.COM_FIELD_LIST:
		return fmt.Sprintf("fieldlist [%s]", data)
	case mysql.COM_STMT_PREPARE:
		return fmt.Sprintf("STMT_PREPARE: %s", hack.String(data))
	case mysql.COM_STMT_EXECUTE:
		return fmt.Sprintf("STMT_EXECUTE [%s]", data)
	case mysql.COM_STMT_CLOSE:
		return fmt.Sprintf("STMT_CLOSE [%s]", data)
	case mysql.COM_STMT_SEND_LONG_DATA:
		return fmt.Sprintf("STMT_SEND_LOG_DATA [%s]", data)
	case mysql.COM_STMT_RESET:
		return fmt.Sprintf("STMT_RESET [%s]", data)
	default:
		return fmt.Sprintf("command %d : [%s]", cmd, data)
	}
}

func (c *conbuf) readPacket() ([]byte, error) {
	header := []byte{0, 0, 0, 0}

	if _, err := io.ReadFull(c.in, header); err != nil {
		return nil, err
	}
	c.readSize += int64(len(header))

	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if length < 1 {
		return nil, fmt.Errorf("invalid payload length %d", length)
	}

	sequence := uint8(header[3])

	if sequence != c.sequence {
		return nil, fmt.Errorf("invalid sequence %d != %d", sequence, c.sequence)
	}

	c.sequence++

	data := make([]byte, length)
	if _, err := io.ReadFull(c.in, data); err != nil {
		return nil, err
	}
	c.readSize += int64(length)

	if length < maxPayloadLen {
		return data, nil
	}

	buf, err := c.readPacket()
	if err != nil {
		return nil, err
	}
	return append(data, buf...), nil
}
