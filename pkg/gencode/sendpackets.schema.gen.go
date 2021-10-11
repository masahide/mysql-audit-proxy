package gencode

import (
	"io"
	"time"
	"unsafe"
)

var (
	_ = unsafe.Sizeof(0)
	_ = io.ReadFull
	_ = time.Now()
)

type SendPackets struct {
	Datetime     int64  `json:"time"` // unix time
	ConnectionID uint32 `json:"id,omitempty"`
	User         string `json:"user,omitempty"`
	Db           string `json:"db,omitempty"`
	Addr         string `json:"addr,omitempty"`
	State        string `json:"state,omitempty"`   // 5
	Err          string `json:"err,omitempty"`     // 6
	Packets      []byte `json:"packets,omitempty"` // 7
	Cmd          string `json:"cmd,omitempty"`
}

func (d *SendPackets) Size() (s uint64) {

	{
		l := uint64(len(d.User))

		{

			t := l
			for t >= 0x80 {
				t >>= 7
				s++
			}
			s++

		}
		s += l
	}
	{
		l := uint64(len(d.Db))

		{

			t := l
			for t >= 0x80 {
				t >>= 7
				s++
			}
			s++

		}
		s += l
	}
	{
		l := uint64(len(d.Addr))

		{

			t := l
			for t >= 0x80 {
				t >>= 7
				s++
			}
			s++

		}
		s += l
	}
	{
		l := uint64(len(d.State))

		{

			t := l
			for t >= 0x80 {
				t >>= 7
				s++
			}
			s++

		}
		s += l
	}
	{
		l := uint64(len(d.Err))

		{

			t := l
			for t >= 0x80 {
				t >>= 7
				s++
			}
			s++

		}
		s += l
	}
	{
		l := uint64(len(d.Packets))

		{

			t := l
			for t >= 0x80 {
				t >>= 7
				s++
			}
			s++

		}
		s += l
	}
	{
		l := uint64(len(d.Cmd))

		{

			t := l
			for t >= 0x80 {
				t >>= 7
				s++
			}
			s++

		}
		s += l
	}
	s += 12
	return
}
func (d *SendPackets) Marshal(buf []byte) ([]byte, error) {
	size := d.Size()
	{
		if uint64(cap(buf)) >= size {
			buf = buf[:size]
		} else {
			buf = make([]byte, size)
		}
	}
	i := uint64(0)

	{

		buf[0+0] = byte(d.Datetime >> 0)

		buf[1+0] = byte(d.Datetime >> 8)

		buf[2+0] = byte(d.Datetime >> 16)

		buf[3+0] = byte(d.Datetime >> 24)

		buf[4+0] = byte(d.Datetime >> 32)

		buf[5+0] = byte(d.Datetime >> 40)

		buf[6+0] = byte(d.Datetime >> 48)

		buf[7+0] = byte(d.Datetime >> 56)

	}
	{

		buf[0+8] = byte(d.ConnectionID >> 0)

		buf[1+8] = byte(d.ConnectionID >> 8)

		buf[2+8] = byte(d.ConnectionID >> 16)

		buf[3+8] = byte(d.ConnectionID >> 24)

	}
	{
		l := uint64(len(d.User))

		{

			t := uint64(l)

			for t >= 0x80 {
				buf[i+12] = byte(t) | 0x80
				t >>= 7
				i++
			}
			buf[i+12] = byte(t)
			i++

		}
		copy(buf[i+12:], d.User)
		i += l
	}
	{
		l := uint64(len(d.Db))

		{

			t := uint64(l)

			for t >= 0x80 {
				buf[i+12] = byte(t) | 0x80
				t >>= 7
				i++
			}
			buf[i+12] = byte(t)
			i++

		}
		copy(buf[i+12:], d.Db)
		i += l
	}
	{
		l := uint64(len(d.Addr))

		{

			t := uint64(l)

			for t >= 0x80 {
				buf[i+12] = byte(t) | 0x80
				t >>= 7
				i++
			}
			buf[i+12] = byte(t)
			i++

		}
		copy(buf[i+12:], d.Addr)
		i += l
	}
	{
		l := uint64(len(d.State))

		{

			t := uint64(l)

			for t >= 0x80 {
				buf[i+12] = byte(t) | 0x80
				t >>= 7
				i++
			}
			buf[i+12] = byte(t)
			i++

		}
		copy(buf[i+12:], d.State)
		i += l
	}
	{
		l := uint64(len(d.Err))

		{

			t := uint64(l)

			for t >= 0x80 {
				buf[i+12] = byte(t) | 0x80
				t >>= 7
				i++
			}
			buf[i+12] = byte(t)
			i++

		}
		copy(buf[i+12:], d.Err)
		i += l
	}
	{
		l := uint64(len(d.Packets))

		{

			t := uint64(l)

			for t >= 0x80 {
				buf[i+12] = byte(t) | 0x80
				t >>= 7
				i++
			}
			buf[i+12] = byte(t)
			i++

		}
		copy(buf[i+12:], d.Packets)
		i += l
	}
	{
		l := uint64(len(d.Cmd))

		{

			t := uint64(l)

			for t >= 0x80 {
				buf[i+12] = byte(t) | 0x80
				t >>= 7
				i++
			}
			buf[i+12] = byte(t)
			i++

		}
		copy(buf[i+12:], d.Cmd)
		i += l
	}
	return buf[:i+12], nil
}

func (d *SendPackets) Unmarshal(buf []byte) (uint64, error) {
	i := uint64(0)

	{

		d.Datetime = 0 | (int64(buf[i+0+0]) << 0) | (int64(buf[i+1+0]) << 8) | (int64(buf[i+2+0]) << 16) | (int64(buf[i+3+0]) << 24) | (int64(buf[i+4+0]) << 32) | (int64(buf[i+5+0]) << 40) | (int64(buf[i+6+0]) << 48) | (int64(buf[i+7+0]) << 56)

	}
	{

		d.ConnectionID = 0 | (uint32(buf[i+0+8]) << 0) | (uint32(buf[i+1+8]) << 8) | (uint32(buf[i+2+8]) << 16) | (uint32(buf[i+3+8]) << 24)

	}
	{
		l := uint64(0)

		{

			bs := uint8(7)
			t := uint64(buf[i+12] & 0x7F)
			for buf[i+12]&0x80 == 0x80 {
				i++
				t |= uint64(buf[i+12]&0x7F) << bs
				bs += 7
			}
			i++

			l = t

		}
		d.User = string(buf[i+12 : i+12+l])
		i += l
	}
	{
		l := uint64(0)

		{

			bs := uint8(7)
			t := uint64(buf[i+12] & 0x7F)
			for buf[i+12]&0x80 == 0x80 {
				i++
				t |= uint64(buf[i+12]&0x7F) << bs
				bs += 7
			}
			i++

			l = t

		}
		d.Db = string(buf[i+12 : i+12+l])
		i += l
	}
	{
		l := uint64(0)

		{

			bs := uint8(7)
			t := uint64(buf[i+12] & 0x7F)
			for buf[i+12]&0x80 == 0x80 {
				i++
				t |= uint64(buf[i+12]&0x7F) << bs
				bs += 7
			}
			i++

			l = t

		}
		d.Addr = string(buf[i+12 : i+12+l])
		i += l
	}
	{
		l := uint64(0)

		{

			bs := uint8(7)
			t := uint64(buf[i+12] & 0x7F)
			for buf[i+12]&0x80 == 0x80 {
				i++
				t |= uint64(buf[i+12]&0x7F) << bs
				bs += 7
			}
			i++

			l = t

		}
		d.State = string(buf[i+12 : i+12+l])
		i += l
	}
	{
		l := uint64(0)

		{

			bs := uint8(7)
			t := uint64(buf[i+12] & 0x7F)
			for buf[i+12]&0x80 == 0x80 {
				i++
				t |= uint64(buf[i+12]&0x7F) << bs
				bs += 7
			}
			i++

			l = t

		}
		d.Err = string(buf[i+12 : i+12+l])
		i += l
	}
	{
		l := uint64(0)

		{

			bs := uint8(7)
			t := uint64(buf[i+12] & 0x7F)
			for buf[i+12]&0x80 == 0x80 {
				i++
				t |= uint64(buf[i+12]&0x7F) << bs
				bs += 7
			}
			i++

			l = t

		}
		if uint64(cap(d.Packets)) >= l {
			d.Packets = d.Packets[:l]
		} else {
			d.Packets = make([]byte, l)
		}
		copy(d.Packets, buf[i+12:])
		i += l
	}
	{
		l := uint64(0)

		{

			bs := uint8(7)
			t := uint64(buf[i+12] & 0x7F)
			for buf[i+12]&0x80 == 0x80 {
				i++
				t |= uint64(buf[i+12]&0x7F) << bs
				bs += 7
			}
			i++

			l = t

		}
		d.Cmd = string(buf[i+12 : i+12+l])
		i += l
	}
	return i + 12, nil
}
