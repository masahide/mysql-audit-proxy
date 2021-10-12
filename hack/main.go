package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

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

func main() {
	var jsonFlag bool
	flag.BoolVar(&jsonFlag, "json", jsonFlag, "json log file mode")
	flag.Parse()
	args := flag.Args()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var in io.ReadSeekCloser
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

	scanner := bufio.NewScanner(in)
	onComma := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		i := bytes.Index(data, []byte{0, 0, 0, 3})
		if i > 0 {
			return i + 4, data[:i], nil
		}
		if !atEOF {
			return 0, nil, nil
		}
		return 0, data, bufio.ErrFinalToken
	}
	s := &SendPackets{}
	scanner.Split(onComma)
	for scanner.Scan() {
		b := scanner.Bytes()
		i := getHeader(b)
		if i >= 0 {
			s.Unmarshal(b[i+4:])
			b = b[0:i]
		}
		s.Cmd = ""
		if len(b) > 0 {
			s.Cmd = fmt.Sprintf("%q", b)
		}
		s, _ := json.Marshal(s)
		fmt.Println(string(s))
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading input:", err)
	}

}

// SendPackets tx packets
type SendPackets struct {
	Datetime     time.Time `json:"time"`
	ConnectionID uint32    `json:"id,omitempty"`
	User         string    `json:"user,omitempty"`
	Db           string    `json:"db,omitempty"`
	Addr         string    `json:"addr,omitempty"`
	State        string    `json:"state,omitempty"`   // 5
	Err          string    `json:"err,omitempty"`     // 6
	Packets      []byte    `json:"packets,omitempty"` // 7
	Cmd          string    `json:"cmd,omitempty"`     // 8
}

var intconv = binary.BigEndian

// Colfer configuration attributes
var (
	// ColferSizeMax is the upper limit for serial byte sizes.
	ColferSizeMax = 2 * 1024 * 1024 * 1024
)

// ColferMax signals an upper limit breach.
type ColferMax string

// Error honors the error interface.
func (m ColferMax) Error() string { return string(m) }

// Unmarshal decodes data as Colfer and returns the number of bytes read.
// The error return options are io.EOF, mysql.ColferError and mysql.ColferMax.
func (o *SendPackets) Unmarshal(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, io.EOF
	}
	header := data[0]
	i := 1

	if header == 0 {
		start := i
		i += 8
		if i >= len(data) {
			goto eof
		}
		o.Datetime = time.Unix(int64(intconv.Uint32(data[start:])), int64(intconv.Uint32(data[start+4:]))).In(time.UTC)
		header = data[i]
		i++
	} else if header == 0|0x80 {
		start := i
		i += 12
		if i >= len(data) {
			goto eof
		}
		o.Datetime = time.Unix(int64(intconv.Uint64(data[start:])), int64(intconv.Uint32(data[start+8:]))).In(time.UTC)
		header = data[i]
		i++
	}

	if header == 1 {
		start := i
		i++
		if i >= len(data) {
			goto eof
		}
		x := uint32(data[start])

		if x >= 0x80 {
			x &= 0x7f
			for shift := uint(7); ; shift += 7 {
				b := uint32(data[i])
				i++
				if i >= len(data) {
					goto eof
				}

				if b < 0x80 {
					x |= b << shift
					break
				}
				x |= (b & 0x7f) << shift
			}
		}
		o.ConnectionID = x

		header = data[i]
		i++
	} else if header == 1|0x80 {
		start := i
		i += 4
		if i >= len(data) {
			goto eof
		}
		o.ConnectionID = intconv.Uint32(data[start:])
		header = data[i]
		i++
	}

	if header == 2 {
		if i >= len(data) {
			goto eof
		}
		x := uint(data[i])
		i++

		if x >= 0x80 {
			x &= 0x7f
			for shift := uint(7); ; shift += 7 {
				if i >= len(data) {
					goto eof
				}
				b := uint(data[i])
				i++

				if b < 0x80 {
					x |= b << shift
					break
				}
				x |= (b & 0x7f) << shift
			}
		}

		if x > uint(ColferSizeMax) {
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.SendPackets.User size %d exceeds %d bytes", x, ColferSizeMax))
		}

		start := i
		i += int(x)
		if i >= len(data) {
			goto eof
		}
		o.User = string(data[start:i])

		header = data[i]
		i++
	}

	if header == 3 {
		if i >= len(data) {
			goto eof
		}
		x := uint(data[i])
		i++

		if x >= 0x80 {
			x &= 0x7f
			for shift := uint(7); ; shift += 7 {
				if i >= len(data) {
					goto eof
				}
				b := uint(data[i])
				i++

				if b < 0x80 {
					x |= b << shift
					break
				}
				x |= (b & 0x7f) << shift
			}
		}

		if x > uint(ColferSizeMax) {
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.SendPackets.Db size %d exceeds %d bytes", x, ColferSizeMax))
		}

		start := i
		i += int(x)
		if i >= len(data) {
			goto eof
		}
		o.Db = string(data[start:i])

		header = data[i]
		i++
	}

	if header == 4 {
		if i >= len(data) {
			goto eof
		}
		x := uint(data[i])
		i++

		if x >= 0x80 {
			x &= 0x7f
			for shift := uint(7); ; shift += 7 {
				if i >= len(data) {
					goto eof
				}
				b := uint(data[i])
				i++

				if b < 0x80 {
					x |= b << shift
					break
				}
				x |= (b & 0x7f) << shift
			}
		}

		if x > uint(ColferSizeMax) {
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.SendPackets.Addr size %d exceeds %d bytes", x, ColferSizeMax))
		}

		start := i
		i += int(x)
		if i >= len(data) {
			goto eof
		}
		o.Addr = string(data[start:i])

		header = data[i]
		i++
	}

	if header == 5 {
		if i >= len(data) {
			goto eof
		}
		x := uint(data[i])
		i++

		if x >= 0x80 {
			x &= 0x7f
			for shift := uint(7); ; shift += 7 {
				if i >= len(data) {
					goto eof
				}
				b := uint(data[i])
				i++

				if b < 0x80 {
					x |= b << shift
					break
				}
				x |= (b & 0x7f) << shift
			}
		}

		if x > uint(ColferSizeMax) {
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.SendPackets.State size %d exceeds %d bytes", x, ColferSizeMax))
		}

		start := i
		i += int(x)
		if i >= len(data) {
			goto eof
		}
		o.State = string(data[start:i])

		header = data[i]
		i++
	}

	if header == 6 {
		if i >= len(data) {
			goto eof
		}
		x := uint(data[i])
		i++

		if x >= 0x80 {
			x &= 0x7f
			for shift := uint(7); ; shift += 7 {
				if i >= len(data) {
					goto eof
				}
				b := uint(data[i])
				i++

				if b < 0x80 {
					x |= b << shift
					break
				}
				x |= (b & 0x7f) << shift
			}
		}

		if x > uint(ColferSizeMax) {
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.SendPackets.Err size %d exceeds %d bytes", x, ColferSizeMax))
		}

		i += int(x)
		if i >= len(data) {
			goto eof
		}
		header = data[i]
		i++
	}

	if header == 7 {
		if i >= len(data) {
			goto eof
		}
		x := uint(data[i])
		i++

		if x >= 0x80 {
			x &= 0x7f
			for shift := uint(7); ; shift += 7 {
				if i >= len(data) {
					goto eof
				}
				b := uint(data[i])
				i++

				if b < 0x80 {
					x |= b << shift
					break
				}
				x |= (b & 0x7f) << shift
			}
		}

		if x > uint(ColferSizeMax) {
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.SendPackets.Packets size %d exceeds %d bytes", x, ColferSizeMax))
		}
		v := make([]byte, int(x))

		i += len(v)
		if i >= len(data) {
			goto eof
		}
		//copy(v, data[start:i])
		//o.Packets = v

		header = data[i]
		i++
	}

	if header == 8 {
		if i >= len(data) {
			goto eof
		}
		x := uint(data[i])
		i++

		if x >= 0x80 {
			x &= 0x7f
			for shift := uint(7); ; shift += 7 {
				if i >= len(data) {
					goto eof
				}
				b := uint(data[i])
				i++

				if b < 0x80 {
					x |= b << shift
					break
				}
				x |= (b & 0x7f) << shift
			}
		}

		if x > uint(ColferSizeMax) {
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.SendPackets.Cmd size %d exceeds %d bytes", x, ColferSizeMax))
		}

		start := i
		i += int(x)
		if i >= len(data) {
			goto eof
		}
		o.Cmd = string(data[start:i])

		header = data[i]
		i++
	}

	if header != 0x7f {
		return 0, nil
	}
	if i < ColferSizeMax {
		return i, nil
	}
eof:
	if i >= ColferSizeMax {
		return 0, ColferMax(fmt.Sprintf("colfer: struct mysql.SendPackets size exceeds %d bytes", ColferSizeMax))
	}
	return 0, io.EOF
}

func isHead(b []byte) bool {
	if b[4] == 0 && b[4+1+8] == 1 && (b[4+1+8+2] == 2 || b[4+1+8+3] == 2 || b[4+1+8+4] == 2) {
		return true
	}
	return false
}

func getHeader(b []byte) int {
	for i := 0; i < len(b) && len(b[i:]) > 20; i++ {
		if isHead(b[i:]) {
			return i
		}
	}
	return -1
}
