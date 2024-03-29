package colfer

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// ColferSendPackets tx packets
type ColferSendPackets struct {
	Datetime     time.Time `json:"time"`
	ConnectionID uint32    `json:"id,omitempty"`
	User         string    `json:"user,omitempty"`
	Db           string    `json:"db,omitempty"`
	Addr         string    `json:"addr,omitempty"`
	State        string    `json:"state,omitempty"`   // 5
	Err          string    `json:"err,omitempty"`     // 6
	Packets      []byte    `json:"packets,omitempty"` // 7
	Cmd          string    `json:"cmd,omitempty"`
}

var intconv = binary.BigEndian

// Colfer configuration attributes
var (
	// ColferSizeMax is the upper limit for serial byte sizes.
	ColferSizeMax = 2 * 1024 * 1024 * 10
)

// ColferMax signals an upper limit breach.
type ColferMax string

// Error honors the error interface.
func (m ColferMax) Error() string { return string(m) }

// ColferError signals a data mismatch as as a byte index.
type ColferError int

// Error honors the error interface.
func (i ColferError) Error() string {
	return fmt.Sprintf("colfer: unknown header at byte %d", i)
}

// ColferTail signals data continuation as a byte index.
type ColferTail int

// Error honors the error interface.
func (i ColferTail) Error() string {
	return fmt.Sprintf("colfer: data continuation at byte %d", i)
}

// MarshalTo encodes o as Colfer into buf and returns the number of bytes written.
// If the buffer is too small, MarshalTo will panic.
func (o *ColferSendPackets) MarshalTo(buf []byte) int {
	var i int

	if v := o.Datetime; !v.IsZero() {
		s, ns := uint64(v.Unix()), uint32(v.Nanosecond())
		if s < 1<<32 {
			buf[i] = 0
			intconv.PutUint32(buf[i+1:], uint32(s))
			i += 5
		} else {
			buf[i] = 0 | 0x80
			intconv.PutUint64(buf[i+1:], s)
			i += 9
		}
		intconv.PutUint32(buf[i:], ns)
		i += 4
	}

	if x := o.ConnectionID; x >= 1<<21 {
		buf[i] = 1 | 0x80
		intconv.PutUint32(buf[i+1:], x)
		i += 5
	} else if x != 0 {
		buf[i] = 1
		i++
		for x >= 0x80 {
			buf[i] = byte(x | 0x80)
			x >>= 7
			i++
		}
		buf[i] = byte(x)
		i++
	}

	if l := len(o.User); l != 0 {
		buf[i] = 2
		i++
		x := uint(l)
		for x >= 0x80 {
			buf[i] = byte(x | 0x80)
			x >>= 7
			i++
		}
		buf[i] = byte(x)
		i++
		i += copy(buf[i:], o.User)
	}

	if l := len(o.Db); l != 0 {
		buf[i] = 3
		i++
		x := uint(l)
		for x >= 0x80 {
			buf[i] = byte(x | 0x80)
			x >>= 7
			i++
		}
		buf[i] = byte(x)
		i++
		i += copy(buf[i:], o.Db)
	}

	if l := len(o.Addr); l != 0 {
		buf[i] = 4
		i++
		x := uint(l)
		for x >= 0x80 {
			buf[i] = byte(x | 0x80)
			x >>= 7
			i++
		}
		buf[i] = byte(x)
		i++
		i += copy(buf[i:], o.Addr)
	}

	if l := len(o.State); l != 0 {
		buf[i] = 5
		i++
		x := uint(l)
		for x >= 0x80 {
			buf[i] = byte(x | 0x80)
			x >>= 7
			i++
		}
		buf[i] = byte(x)
		i++
		i += copy(buf[i:], o.State)
	}

	if l := len(o.Err); l != 0 {
		buf[i] = 6
		i++
		x := uint(l)
		for x >= 0x80 {
			buf[i] = byte(x | 0x80)
			x >>= 7
			i++
		}
		buf[i] = byte(x)
		i++
		i += copy(buf[i:], o.Err)
	}

	if o.Packets != nil {
		if l := len(o.Packets); l != 0 {
			buf[i] = 7
			i++
			x := uint(l)
			for x >= 0x80 {
				buf[i] = byte(x | 0x80)
				x >>= 7
				i++
			}
			buf[i] = byte(x)
			i++
			i += copy(buf[i:], o.Packets)
		}
	}

	if l := len(o.Cmd); l != 0 {
		buf[i] = 8
		i++
		x := uint(l)
		for x >= 0x80 {
			buf[i] = byte(x | 0x80)
			x >>= 7
			i++
		}
		buf[i] = byte(x)
		i++
		i += copy(buf[i:], o.Cmd)
	}

	buf[i] = 0x7f
	i++
	return i
}

// MarshalLen returns the Colfer serial byte size.
// The error return option is mysql.ColferMax.
func (o *ColferSendPackets) MarshalLen() (int, error) {
	l := 1

	if v := o.Datetime; !v.IsZero() {
		if s := uint64(v.Unix()); s < 1<<32 {
			l += 9
		} else {
			l += 13
		}
	}

	if x := o.ConnectionID; x >= 1<<21 {
		l += 5
	} else if x != 0 {
		for l += 2; x >= 0x80; l++ {
			x >>= 7
		}
	}

	if x := len(o.User); x != 0 {
		if x > ColferSizeMax {
			return 0, ColferMax(fmt.Sprintf("colfer: field mysql.ColferSendPackets.User exceeds %d bytes", ColferSizeMax))
		}
		for l += x + 2; x >= 0x80; l++ {
			x >>= 7
		}
	}

	if x := len(o.Db); x != 0 {
		if x > ColferSizeMax {
			return 0, ColferMax(fmt.Sprintf("colfer: field mysql.ColferSendPackets.Db exceeds %d bytes", ColferSizeMax))
		}
		for l += x + 2; x >= 0x80; l++ {
			x >>= 7
		}
	}

	if x := len(o.Addr); x != 0 {
		if x > ColferSizeMax {
			return 0, ColferMax(fmt.Sprintf("colfer: field mysql.ColferSendPackets.Addr exceeds %d bytes", ColferSizeMax))
		}
		for l += x + 2; x >= 0x80; l++ {
			x >>= 7
		}
	}

	if x := len(o.State); x != 0 {
		if x > ColferSizeMax {
			return 0, ColferMax(fmt.Sprintf("colfer: field mysql.ColferSendPackets.State exceeds %d bytes", ColferSizeMax))
		}
		for l += x + 2; x >= 0x80; l++ {
			x >>= 7
		}
	}

	if x := len(o.Err); x != 0 {
		if x > ColferSizeMax {
			return 0, ColferMax(fmt.Sprintf("colfer: field mysql.ColferSendPackets.Err exceeds %d bytes", ColferSizeMax))
		}
		for l += x + 2; x >= 0x80; l++ {
			x >>= 7
		}
	}

	if o.Packets != nil {
		if x := len(o.Packets); x != 0 {
			if x > ColferSizeMax {
				return 0, ColferMax(fmt.Sprintf("colfer: field mysql.ColferSendPackets.Packets exceeds %d bytes", ColferSizeMax))
			}
			for l += x + 2; x >= 0x80; l++ {
				x >>= 7
			}
		}
	}

	if x := len(o.Cmd); x != 0 {
		if x > ColferSizeMax {
			return 0, ColferMax(fmt.Sprintf("colfer: field mysql.ColferSendPackets.Cmd exceeds %d bytes", ColferSizeMax))
		}
		for l += x + 2; x >= 0x80; l++ {
			x >>= 7
		}
	}

	if l > ColferSizeMax {
		return l, ColferMax(fmt.Sprintf("colfer: struct mysql.ColferSendPackets exceeds %d bytes", ColferSizeMax))
	}
	return l, nil
}

// MarshalBinary encodes o as Colfer conform encoding.BinaryMarshaler.
// The error return option is mysql.ColferMax.
func (o *ColferSendPackets) MarshalBinary() (data []byte, err error) {
	l, err := o.MarshalLen()
	if err != nil {
		return nil, err
	}
	data = make([]byte, l)
	o.MarshalTo(data)
	return data, nil
}

// Unmarshal decodes data as Colfer and returns the number of bytes read.
// The error return options are io.EOF, mysql.ColferError and mysql.ColferMax.
func (o *ColferSendPackets) Unmarshal(data []byte) (int, error) {
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
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.ColferSendPackets.User size %d exceeds %d bytes", x, ColferSizeMax))
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
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.ColferSendPackets.Db size %d exceeds %d bytes", x, ColferSizeMax))
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
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.ColferSendPackets.Addr size %d exceeds %d bytes", x, ColferSizeMax))
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
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.ColferSendPackets.State size %d exceeds %d bytes", x, ColferSizeMax))
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
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.ColferSendPackets.Err size %d exceeds %d bytes", x, ColferSizeMax))
		}

		start := i
		i += int(x)
		if i >= len(data) {
			goto eof
		}
		o.Err = string(data[start:i])

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
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.ColferSendPackets.Packets size %d exceeds %d bytes", x, ColferSizeMax))
		}
		v := make([]byte, int(x))

		start := i
		i += len(v)
		if i >= len(data) {
			goto eof
		}
		copy(v, data[start:i])
		o.Packets = v

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
			return 0, ColferMax(fmt.Sprintf("colfer: mysql.ColferSendPackets.Cmd size %d exceeds %d bytes", x, ColferSizeMax))
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
		return 0, ColferError(i - 1)
	}
	if i < ColferSizeMax {
		return i, nil
	}
eof:
	if i >= ColferSizeMax {
		return 0, ColferMax(fmt.Sprintf("colfer: struct mysql.ColferSendPackets size exceeds %d bytes", ColferSizeMax))
	}
	return 0, io.EOF
}

// UnmarshalBinary decodes data as Colfer conform encoding.BinaryUnmarshaler.
// The error return options are io.EOF, mysql.ColferError, mysql.ColferTail and mysql.ColferMax.
func (o *ColferSendPackets) UnmarshalBinary(data []byte) error {
	i, err := o.Unmarshal(data)
	if i < len(data) && err == nil {
		return ColferTail(i)
	}
	return err
}
