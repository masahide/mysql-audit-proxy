package mysql

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/siddontang/mixer/mysql"
)

// ProxyClient proxy <-> mysql server
type ProxyClient struct {
	client     *ClientConn
	conn       net.Conn
	pkg        *mysql.PacketIO
	addr       string
	user       string
	password   string
	db         string
	capability uint32
	status     uint16
	collation  mysql.CollationId
	//charset    string
	salt []byte
	//lastPing int64
	//pkgErr error
}

func (pc *ProxyClient) connect(addr string, user string, password string, db string) error {
	pc.addr = addr
	pc.user = user
	pc.password = password
	pc.db = db

	//use utf8
	pc.collation = mysql.DEFAULT_COLLATION_ID
	//pc.charset = mysql.DEFAULT_CHARSET

	return pc.reConnect()
}

func (pc *ProxyClient) reConnect() error {
	var (
		err     error
		netConn net.Conn
	)

	if pc.conn != nil {
		pc.conn.Close()
	}
	n := "tcp"
	if strings.Contains(pc.addr, "/") {
		n = "unix"
	}
	netConn, err = net.Dial(n, pc.addr)
	if err != nil {
		return err
	}
	switch t := netConn.(type) {
	case *net.TCPConn:
		tcpConn := t
		//SetNoDelay controls whether the operating system should delay packet transmission
		// in hopes of sending fewer packets (Nagle's algorithm).
		// The default is true (no delay),
		// meaning that data is sent as soon as possible after a Write.
		//I set this option false.
		// nolint: errcheck
		tcpConn.SetNoDelay(false)
		pc.conn = tcpConn
	default:
		pc.conn = t
	}

	pc.pkg = mysql.NewPacketIO(pc.conn)

	if err := pc.readInitialHandshake(); err != nil {
		pc.conn.Close()
		return err
	}

	if err := pc.writeAuthHandshake(); err != nil {
		pc.conn.Close()
		return err
	}

	if _, err := pc.readOK(); err != nil {
		pc.conn.Close()
		return err
	}

	//we must always use autocommit
	if !pc.isAutoCommit() {
		if _, err := pc.exec("set autocommit = 1"); err != nil {
			pc.conn.Close()
			return err
		}
	}

	//pc.lastPing = time.Now().Unix()

	return nil
}

func (pc *ProxyClient) readInitialHandshake() error {
	data, err := pc.readPacket()
	if err != nil {
		return err
	}

	if data[0] == mysql.ERR_HEADER {
		return errors.New("read initial handshake error")
	}

	if data[0] < mysql.MinProtocolVersion {
		return fmt.Errorf("invalid protocol version %d, must >= 10", data[0])
	}

	//skip mysql version and connection id
	//mysql version end with 0x00
	//connection id length is 4
	pos := 1 + bytes.IndexByte(data[1:], 0x00) + 1 + 4

	pc.salt = append(pc.salt, data[pos:pos+8]...)

	//skip filter
	pos += 8 + 1

	//capability lower 2 bytes
	pc.capability = uint32(binary.LittleEndian.Uint16(data[pos : pos+2]))

	pos += 2

	if len(data) > pos {
		//skip server charset
		//pc.charset = data[pos]
		pos++

		pc.status = binary.LittleEndian.Uint16(data[pos : pos+2])
		pos += 2

		pc.capability = uint32(binary.LittleEndian.Uint16(data[pos:pos+2]))<<16 | pc.capability

		pos += 2

		//skip auth data len or [00]
		//skip reserved (all [00])
		pos += 10 + 1

		// The documentation is ambiguous about the length.
		// The official Python library uses the fixed length 12
		// mysql-proxy also use 12
		// which is not documented but seems to work.
		pc.salt = append(pc.salt, data[pos:pos+12]...)
	}

	return nil
}

func (pc *ProxyClient) writeAuthHandshake() error {
	// Adjust client capability flags based on server support
	capability := mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_SECURE_CONNECTION |
		mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_TRANSACTIONS | mysql.CLIENT_LONG_FLAG

	capability &= pc.capability

	//packet length
	//capbility 4
	//max-packet size 4
	//charset 1
	//reserved all[0] 23
	length := 4 + 4 + 1 + 23

	//username
	length += len(pc.user) + 1

	//we only support secure connection
	auth := mysql.CalcPassword(pc.salt, []byte(pc.password))

	length += 1 + len(auth)

	if len(pc.db) > 0 {
		capability |= mysql.CLIENT_CONNECT_WITH_DB

		length += len(pc.db) + 1
	}

	pc.capability = capability

	data := make([]byte, length+4)

	//capability [32 bit]
	data[4] = byte(capability)
	data[5] = byte(capability >> 8)
	data[6] = byte(capability >> 16)
	data[7] = byte(capability >> 24)

	//MaxPacketSize [32 bit] (none)
	//data[8] = 0x00
	//data[9] = 0x00
	//data[10] = 0x00
	//data[11] = 0x00

	//Charset [1 byte]
	data[12] = byte(pc.collation)

	//Filler [23 bytes] (all 0x00)
	pos := 13 + 23

	//User [null terminated string]
	if len(pc.user) > 0 {
		pos += copy(data[pos:], pc.user)
	}
	//data[pos] = 0x00
	pos++

	// auth [length encoded integer]
	data[pos] = byte(len(auth))
	pos += 1 + copy(data[pos+1:], auth)

	// db [null terminated string]

	if len(pc.db) > 0 {
		/*pos +=*/ copy(data[pos:], pc.db)
		//data[pos] = 0x00
	}

	return pc.writePacket(data)
}

func (pc *ProxyClient) readOK() (*mysql.Result, error) {
	data, err := pc.readPacket()
	if err != nil {
		return nil, err
	}

	switch {
	case data[0] == mysql.OK_HEADER:
		return pc.handleOKPacket(data)
	case data[0] == mysql.ERR_HEADER:
		return nil, pc.handleErrorPacket(data)
	}
	return nil, errors.New("invalid ok packet")
}

func (pc *ProxyClient) writePacket(data []byte) error {
	err := pc.pkg.WritePacket(data)
	//pc.pkgErr = err
	return err
}

func (pc *ProxyClient) readPacket() ([]byte, error) {
	d, err := pc.pkg.ReadPacket()
	//pc.pkgErr = err
	return d, err
}

func (pc *ProxyClient) handleOKPacket(data []byte) (*mysql.Result, error) {
	var n int
	var pos int = 1

	r := new(mysql.Result)

	r.AffectedRows, _, n = mysql.LengthEncodedInt(data[pos:])
	pos += n
	r.InsertId, _, n = mysql.LengthEncodedInt(data[pos:])
	pos += n

	if pc.capability&mysql.CLIENT_PROTOCOL_41 > 0 {
		r.Status = binary.LittleEndian.Uint16(data[pos:])
		pc.status = r.Status
		//pos += 2

		//TODO:strict_mode, check warnings as error
		//Warnings := binary.LittleEndian.Uint16(data[pos:])
		//pos += 2
	} else if pc.capability&mysql.CLIENT_TRANSACTIONS > 0 {
		r.Status = binary.LittleEndian.Uint16(data[pos:])
		pc.status = r.Status
		//pos += 2
	}

	//info
	return r, nil
}
func (pc *ProxyClient) handleErrorPacket(data []byte) error {
	e := new(mysql.SqlError)

	var pos int = 1

	e.Code = binary.LittleEndian.Uint16(data[pos:])
	pos += 2

	if pc.capability&mysql.CLIENT_PROTOCOL_41 > 0 {
		//skip '#'
		pos++
		e.State = string(data[pos : pos+5])
		pos += 5
	}

	e.Message = string(data[pos:])

	return e
}

func (pc *ProxyClient) isAutoCommit() bool {
	return pc.status&mysql.SERVER_STATUS_AUTOCOMMIT > 0
}
func (pc *ProxyClient) exec(query string) (*mysql.Result, error) {
	if err := pc.writeCommandStr(mysql.COM_QUERY, query); err != nil {
		return nil, err
	}

	return pc.readResult(false)
}
func (pc *ProxyClient) writeCommandStr(command byte, arg string) error {
	pc.pkg.Sequence = 0

	length := len(arg) + 1

	data := make([]byte, length+4)

	data[4] = command

	copy(data[5:], arg)

	return pc.writePacket(data)
}
func (pc *ProxyClient) readResult(binary bool) (*mysql.Result, error) {
	data, err := pc.readPacket()
	if err != nil {
		return nil, err
	}

	switch {
	case data[0] == mysql.OK_HEADER:
		return pc.handleOKPacket(data)
	case data[0] == mysql.ERR_HEADER:
		return nil, pc.handleErrorPacket(data)
	case data[0] == mysql.LocalInFile_HEADER:
		return nil, mysql.ErrMalformPacket
	}

	return pc.readResultset(data, binary)
}
func (pc *ProxyClient) readResultset(data []byte, binary bool) (*mysql.Result, error) {
	result := &mysql.Result{
		Status:       0,
		InsertId:     0,
		AffectedRows: 0,

		Resultset: &mysql.Resultset{},
	}

	// column count
	count, _, n := mysql.LengthEncodedInt(data)

	if n-len(data) != 0 {
		return nil, mysql.ErrMalformPacket
	}

	result.Fields = make([]*mysql.Field, count)
	result.FieldNames = make(map[string]int, count)

	if err := pc.readResultColumns(result); err != nil {
		return nil, err
	}

	if err := pc.readResultRows(result, binary); err != nil {
		return nil, err
	}

	return result, nil
}
func (pc *ProxyClient) readResultColumns(result *mysql.Result) (err error) {
	var i int = 0
	var data []byte

	for {
		data, err = pc.readPacket()
		if err != nil {
			return
		}

		// EOF Packet
		if pc.isEOFPacket(data) {
			if pc.capability&mysql.CLIENT_PROTOCOL_41 > 0 {
				//result.Warnings = binary.LittleEndian.Uint16(data[1:])
				//TODO: add strict_mode, warning will be treat as error
				result.Status = binary.LittleEndian.Uint16(data[3:])
				pc.status = result.Status
			}

			if i != len(result.Fields) {
				err = mysql.ErrMalformPacket
			}

			return
		}

		result.Fields[i], err = mysql.FieldData(data).Parse()
		if err != nil {
			return
		}

		result.FieldNames[string(result.Fields[i].Name)] = i

		i++
	}
}
func (pc *ProxyClient) readResultRows(result *mysql.Result, isBinary bool) (err error) {
	var data []byte

	for {
		data, err = pc.readPacket()

		if err != nil {
			return
		}

		// EOF Packet
		if pc.isEOFPacket(data) {
			if pc.capability&mysql.CLIENT_PROTOCOL_41 > 0 {
				//result.Warnings = binary.LittleEndian.Uint16(data[1:])
				//TODO add strict_mode, warning will be treat as error
				result.Status = binary.LittleEndian.Uint16(data[3:])
				pc.status = result.Status
			}

			break
		}

		result.RowDatas = append(result.RowDatas, data)
	}

	result.Values = make([][]interface{}, len(result.RowDatas))

	for i := range result.Values {
		result.Values[i], err = result.RowDatas[i].Parse(result.Fields, isBinary)

		if err != nil {
			return err
		}
	}

	return nil
}

/*
func (pc *ProxyClient) readUntilEOF() (err error) {
	var data []byte

	for {
		data, err = pc.readPacket()

		if err != nil {
			return
		}

		// EOF Packet
		if pc.isEOFPacket(data) {
			return
		}
	}
}
*/

func (pc *ProxyClient) isEOFPacket(data []byte) bool {
	return data[0] == mysql.EOF_HEADER && len(data) <= 5
}
