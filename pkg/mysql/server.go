package mysql

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/masahide/mysql-audit-proxy/pkg/gencode"
	"github.com/masahide/mysql-audit-proxy/pkg/parser"
	"github.com/masahide/rcp/pkg/bytesize"
	"github.com/siddontang/mixer/mysql"
)

const (
	defaultMySQLPort      = "3306"
	defaultMySQLProxyPort = "9696"
)

// nolint:gochecknoglobals
var (
	defaultCapability uint32 = mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_LONG_FLAG |
		mysql.CLIENT_CONNECT_WITH_DB | mysql.CLIENT_PROTOCOL_41 |
		mysql.CLIENT_TRANSACTIONS | mysql.CLIENT_SECURE_CONNECTION
)

// Config Proxy
type Config struct {
	Net             string `yaml:"net"`
	Addr            string `yaml:"addr"`
	AllowIps        string `yaml:"allow_ips"`
	ConfigPath      string
	LogFileName     string
	EncodeType      byte
	LogGzip         bool
	RotateTime      time.Duration
	BufSize         string
	QueueSize       int
	BufferFlushTime time.Duration
}

// NodeConfig node config
type NodeConfig struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Db       string `yaml:"db"`
	Addr     string `yaml:"addr"`
}

// Server  config
type Server struct {
	cfg  *Config
	addr string
	//password string
	listener net.Listener
	allowips []net.IP
	//node     *NodeConfig
	baseConnID uint32
	bs         *buffers
	queue      chan *gencode.SendPackets
	al         *auditLogs
	bufSize    int
}

type buffers struct {
	limit chan struct{}
	pool  sync.Pool
}

func newBuffers(size, n int) *buffers {
	bs := buffers{}
	bs.limit = make(chan struct{}, n)
	bs.pool = sync.Pool{New: func() interface{} {
		sp := gencode.SendPackets{}
		sp.Packets = make([]byte, size)
		return &sp
	}}
	return &bs
}

func (bs *buffers) Get() *gencode.SendPackets {
	bs.limit <- struct{}{} // 空くまで待つ
	return bs.pool.Get().(*gencode.SendPackets)
}

func (bs *buffers) Put(b *gencode.SendPackets) {
	bs.pool.Put(b)
	<-bs.limit // 解放
}

// NewServer new Server
func NewServer(ctx context.Context, cfg *Config) (*Server, error) {
	s := new(Server)

	s.cfg = cfg

	s.addr = cfg.Addr

	s.parseAllowIps()

	s.baseConnID = 10000
	var err error

	lc := net.ListenConfig{
		KeepAlive: 300 * time.Second,
	}
	s.listener, err = lc.Listen(ctx, cfg.Net, s.addr)

	if err != nil {
		return nil, err
	}

	if cfg.Net == "unix" {
		if err = os.Chmod(s.addr, 0777); err != nil {
			return nil, err
		}
	}

	log.Printf("server.NewServer Server running. address %s:%s", cfg.Net, s.addr)
	bufsize, err := bytesize.Parse(s.cfg.BufSize)
	if err != nil {
		log.Fatalf("bufsize:[%s] parse err:%s", s.cfg.BufSize, err)
	}
	s.bufSize = int(bufsize)

	s.queue = make(chan *gencode.SendPackets, s.cfg.QueueSize)
	s.bs = newBuffers(s.bufSize, s.cfg.QueueSize)
	s.al = &auditLogs{
		FileName:   s.cfg.LogFileName,
		RotateTime: s.cfg.RotateTime,
		EncodeType: s.cfg.EncodeType,
		Queue:      s.queue,
		Bs:         s.bs,
		Gzip:       s.cfg.LogGzip,
	}
	return s, nil
}

func (s *Server) newClientConn(conn net.Conn) *ClientConn {
	cc := new(ClientConn)
	switch t := conn.(type) {
	case *net.TCPConn:
		tcpConn := t

		//SetNoDelay controls whether the operating system should delay packet transmission
		// in hopes of sending fewer packets (Nagle's algorithm).
		// The default is true (no delay),
		// meaning that data is sent as soon as possible after a Write.
		//I set this option false.
		// nolint: errcheck
		tcpConn.SetNoDelay(false)
		cc.c = tcpConn
	default:
		cc.c = conn
	}

	cc.pkg = mysql.NewPacketIO(cc.c)
	cc.proxy = s

	cc.pkg.Sequence = 0

	cc.connectionID = atomic.AddUint32(&s.baseConnID, 1)

	cc.status = mysql.SERVER_STATUS_AUTOCOMMIT

	cc.salt = mysql.RandomBuf(20)

	//cc.collation = mysql.DEFAULT_COLLATION_ID
	//cc.charset = mysql.DEFAULT_CHARSET

	cc.bs = s.bs
	cc.queue = s.queue
	return cc
}

func (s *Server) onConn(ctx context.Context, c net.Conn) {
	cc := s.newClientConn(c)

	defer func() {
		err := recover()
		if err != nil {
			buf := make([]byte, 4096)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("Error server.onConn remoteAddr:%s, stack:%s", c.RemoteAddr().String(), string(buf))
		}

		cc.close()
	}()

	if allowConnect := cc.isAllowConnect(); allowConnect {
		err := mysql.NewError(mysql.ER_ACCESS_DENIED_ERROR, "ip address access denied by mysqlproxy.")
		if err := cc.writeError(err); err != nil {
			log.Printf("onConn.writeError:%s", err)
		}
		cc.close()
		return
	}
	if err := cc.handshake(); err != nil {
		log.Printf("Error server.onConn  %s", err.Error())
		c.Close()
		return
	}

	cc.run(ctx)
}

func (s *Server) parseAllowIps() {
	cfg := s.cfg
	if len(cfg.AllowIps) == 0 {
		return
	}
	ipVec := strings.Split(cfg.AllowIps, ",")
	s.allowips = make([]net.IP, 0, 10)
	for _, ip := range ipVec {
		s.allowips = append(s.allowips, net.ParseIP(strings.TrimSpace(ip)))
	}
}

// Run server main process
func (s *Server) Run(ctx context.Context) error {
	logErrCh := make(chan error, 1)
	go s.al.logWorker(ctx, logErrCh)
	go func() {
		<-ctx.Done()
		s.listener.Close()
		close(s.queue)
	}()
L:
	for {
		aConn, err := s.listener.Accept()
		if err != nil {
			log.Printf("listner.Accept %s", err.Error())
			select {
			case <-ctx.Done():
				break L
			default:
			}
			continue
		}
		go s.onConn(ctx, aConn)
	}
	err := <-logErrCh
	if err != nil {
		log.Printf("logWorker err:%s", err)
	}
	return err
}

// ClientConn client <-> proxy
type ClientConn struct {
	pkg          *mysql.PacketIO
	c            net.Conn
	proxy        *Server
	capability   uint32
	connectionID uint32
	status       uint16
	//collation    mysql.CollationId
	//charset      string
	user string
	db   string
	salt []byte
	//lastInsertId int64
	//affectedRows int64
	node *NodeConfig

	bs    *buffers
	queue chan *gencode.SendPackets
}

func (cc *ClientConn) close() error {
	if cc.c == nil {
		return nil
	}
	log.Printf("close client ip:%s", cc.c.RemoteAddr().String())
	if err := cc.c.Close(); err != nil {
		return err
	}
	cc.c = nil
	return nil
}
func (cc *ClientConn) isAllowConnect() bool {
	return false
	/*
		clientHost, _, err := net.SplitHostPort(cc.c.RemoteAddr().String())
		if err != nil {
			fmt.Println(err)
		}
		clientIP := net.ParseIP(clientHost)

		ipVec := cc.proxy.allowips
		if ipVecLen := len(ipVec); ipVecLen == 0 {
			return true
		}
		for _, ip := range ipVec {
			if ip.Equal(clientIP) {
				return true
			}
		}

		log.Printf("Error server.isAllowConnect [Access denied]. address:%s ", cc.c.RemoteAddr().String())
		return false
	*/
}

func (cc *ClientConn) writeError(e error) error {
	var m *mysql.SqlError
	var ok bool
	if m, ok = e.(*mysql.SqlError); !ok {
		m = mysql.NewError(mysql.ER_UNKNOWN_ERROR, e.Error())
	}

	data := make([]byte, 4, 16+len(m.Message))

	data = append(data, mysql.ERR_HEADER)
	data = append(data, byte(m.Code), byte(m.Code>>8))

	if cc.capability&mysql.CLIENT_PROTOCOL_41 > 0 {
		data = append(data, '#')
		data = append(data, m.State...)
	}

	data = append(data, m.Message...)

	return cc.writePacket(data)
}
func (cc *ClientConn) handshake() error {
	if err := cc.writeInitialHandshake(); err != nil {
		log.Printf("Error server.handshake  [%s] connectionID:%d", err.Error(), cc.connectionID)
		return err
	}

	if err := cc.readHandshakeResponse(); err != nil {
		log.Printf("Error server.readHandshakeResponse [%s] connectionID:%d", err.Error(), cc.connectionID)

		if err := cc.writeError(err); err != nil {
			log.Printf("handshake.writeError:%s", err)
		}

		return err
	}

	if err := cc.writeOK(nil); err != nil {
		log.Printf("Error server.readHandshakeResponse [write ok fail] [%s] connectionID:%d", err.Error(), cc.connectionID)
		return err
	}

	cc.pkg.Sequence = 0

	return nil
}
func (cc *ClientConn) writeOK(r *mysql.Result) error {
	if r == nil {
		r = &mysql.Result{Status: cc.status}
	}
	data := make([]byte, 4, 32)

	data = append(data, mysql.OK_HEADER)

	data = append(data, mysql.PutLengthEncodedInt(r.AffectedRows)...)
	data = append(data, mysql.PutLengthEncodedInt(r.InsertId)...)

	if cc.capability&mysql.CLIENT_PROTOCOL_41 > 0 {
		data = append(data, byte(r.Status), byte(r.Status>>8))
		data = append(data, 0, 0)
	}

	return cc.writePacket(data)
}

func (cc *ClientConn) writeInitialHandshake() error {
	data := make([]byte, 4, 128)

	//min version 10
	data = append(data, 10)

	//server version[00]
	data = append(data, mysql.ServerVersion...)
	data = append(data, 0)

	//connection id
	data = append(data,
		byte(cc.connectionID),
		byte(cc.connectionID>>8),
		byte(cc.connectionID>>16),
		byte(cc.connectionID>>24))

	//auth-plugin-data-part-1
	data = append(data, cc.salt[0:8]...)

	//filter [00]
	data = append(data, 0)

	//capability flag lower 2 bytes, using default capability here
	data = append(data, byte(defaultCapability), byte(defaultCapability>>8))

	//charset, utf-8 default
	data = append(data, uint8(mysql.DEFAULT_COLLATION_ID))

	//status
	data = append(data, byte(cc.status), byte(cc.status>>8))

	//below 13 byte may not be used
	//capability flag upper 2 bytes, using default capability here
	data = append(data, byte(defaultCapability>>16), byte(defaultCapability>>24))

	//filter [0x15], for wireshark dump, value is 0x15
	data = append(data, 0x15)

	//reserved 10 [00]
	data = append(data, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

	//auth-plugin-data-part-2
	data = append(data, cc.salt[8:]...)

	//filter [00]
	data = append(data, 0)

	return cc.writePacket(data)
}

func (cc *ClientConn) getNodeFromConfigFile() (*NodeConfig, error) {
	if cc.proxy.cfg.ConfigPath == "" {
		return nil, nil
	}
	if strings.Contains(cc.user, ";") {
		return nil, nil
	}
	p := parser.Parser{
		ConfigPath: cc.proxy.cfg.ConfigPath,
	}
	proxyUsers, err := p.Parse()
	if err != nil {
		return nil, err
	}
	substrings := strings.Split(cc.user, "@")
	if len(substrings) != 2 {
		return nil, fmt.Errorf("invalid user: %s", cc.user)
	}
	proxyUser := proxyUsers[substrings[0]]
	proxyAddr := proxyUser.ProxyServer
	if !strings.Contains(proxyAddr, ":") {
		proxyAddr = fmt.Sprintf("%s:%s", proxyAddr, defaultMySQLProxyPort)
	}
	dbAddr := substrings[1]
	if !strings.Contains(dbAddr, ":") {
		dbAddr = fmt.Sprintf("%s:%s", dbAddr, defaultMySQLPort)
	}
	node := &NodeConfig{
		User: fmt.Sprintf(
			"%s:%s@%s;%s",
			proxyUser.Username,
			proxyUser.Password,
			proxyAddr,
			dbAddr,
		),
		Password: proxyUser.Password,
		Addr:     proxyAddr,
	}
	return node, nil
}

// nolint:gochecknoglobals
//var nodeRe = regexp.MustCompile(`^(.+):(.*)@(.+:\d+);(.+:\d+)(;(.+))?$`)
var nodeRe = regexp.MustCompile(`^(.+):(.*)@(.+:\d+)(;([^;]+))?$`)

// getNode parse from cc.user
// example: user:pass@proxy_host:proxy_port;db_host:db_port;db_name
// pass and db_name is optional
// example: user:@proxy_host:proxy_port;db_host:db_port
func (cc *ClientConn) getNode() error {
	var err error
	if cc.node, err = cc.getNodeFromConfigFile(); err != nil {
		log.Print(err)
	}
	if cc.node != nil {
		return nil
	}
	matches := nodeRe.FindStringSubmatch(cc.user)
	if len(matches) != 6 {
		return fmt.Errorf("invalid user: %s", cc.user)
	}
	cc.node = &NodeConfig{
		User:     matches[1],
		Password: matches[2],
		Addr:     matches[3],
	}
	log.Printf("user:[%s] passwd[xxx] host:[%s]", cc.node.User, cc.node.Addr)
	return nil
}
func (cc *ClientConn) readHandshakeResponse() error {
	data, err := cc.readPacket()

	if err != nil {
		return err
	}

	pos := 0

	//capability
	cc.capability = binary.LittleEndian.Uint32(data[:4])
	pos += 4

	//skip max packet size
	pos += 4

	//charset, skip, if you want to use another charset, use set names
	//cc.collation = CollationId(data[pos])
	pos++

	//skip reserved 23[00]
	pos += 23

	//user name
	cc.user = string(data[pos : pos+bytes.IndexByte(data[pos:], 0)])
	if err := cc.getNode(); err != nil {
		return err
	}
	pos += len(cc.user) + 1

	//auth length and auth
	authLen := int(data[pos])
	pos++
	/*
		auth := data[pos : pos+authLen]

			checkAuth := mysql.CalcPassword(cc.salt, []byte(cc.node.Password))
			if !bytes.Equal(auth, checkAuth) {
				log.Printf("Error ClientConn.readHandshakeResponse. auth:%v, checkAuth:%v, Password:%v",
					auth, checkAuth, cc.node.Password)
				return mysql.NewDefaultError(mysql.ER_ACCESS_DENIED_ERROR, cc.c.RemoteAddr().String(), cc.user, "Yes")
			}
	*/

	pos += authLen

	if cc.capability&mysql.CLIENT_CONNECT_WITH_DB > 0 {
		if len(data[pos:]) == 0 {
			return nil
		}

		db := string(data[pos : pos+bytes.IndexByte(data[pos:], 0)])
		//pos += len(cc.db) + 1

		if err := cc.useDB(db); err != nil {
			return err
		}
	}

	return nil
}
func (cc *ClientConn) useDB(db string) error {
	cc.db = db
	cc.node.Db = db
	return nil
}

func (cc *ClientConn) readPacket() ([]byte, error) {
	return cc.pkg.ReadPacket()
}

func (cc *ClientConn) writePacket(data []byte) error {
	return cc.pkg.WritePacket(data)
}

func (cc *ClientConn) run(ctx context.Context) {
	defer func() {
		r := recover()
		if err, ok := r.(error); ok {
			buf := make([]byte, 4096)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("Error ClientConn.Run [%s] stak:%s", err.Error(), string(buf))
		}
		cc.close()
	}()

	log.Printf("Success Handshake. fromAddr:%s", cc.c.RemoteAddr())
	pc := ProxyClient{}
	db := cc.node
	if err := pc.connect(db.Addr, db.User, db.Password, db.Db); err != nil {
		log.Printf("pc.connect err:%s", err)
		return
	}
	log.Printf("Success Connect. toAddr:%s", pc.conn.RemoteAddr())

	// nolint: errcheck
	cc.sendState(ctx, "connect")
	wg := sync.WaitGroup{}
	cctx, cancel := context.WithCancel(ctx)
	wg.Add(2)
	go func() {
		_, err := io.Copy(cc.c, pc.conn)
		if err != nil {
			log.Printf("copy cc.c pc.conn err:%s", err)
		}
		cancel()
		wg.Done()
	}()
	go func() {
		cc.sendWorker(cctx, pc.conn, cc.c)
		cancel()
		wg.Done()
	}()
	wg.Wait()
	err := pc.Close()
	if err != nil {
		log.Printf("ProxyClient Close err:%s", err)
	}
	// nolint: errcheck
	cc.sendState(ctx, "disconnect")
}

func (cc *ClientConn) sendState(ctx context.Context, state string) error {
	sp := cc.getSendPackets()
	sp.State = state
	sp.Packets = sp.Packets[:0]
	return cc.postData(ctx, sp)
}

func (cc *ClientConn) getSendPackets() *gencode.SendPackets {
	sp := cc.bs.Get()
	sp.Datetime = time.Now().Unix()
	sp.User = cc.node.User
	sp.Db = cc.node.Db
	sp.Addr = cc.node.Addr
	sp.ConnectionID = cc.connectionID
	sp.State = "est"
	return sp
}

/*
func putDebugData(data interface{}) {
	file, err := os.OpenFile("tmplog.json", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	err = enc.Encode(data)
	if err != nil {
		log.Fatal(err)
	}
}
*/

func (cc *ClientConn) postData(ctx context.Context, sp *gencode.SendPackets) error {
	//putDebugData(sp) // TODO: debug
	select {
	case <-ctx.Done():
		return ctx.Err()
	case cc.queue <- sp:
		sp = nil
	}
	return nil
}

func (cc *ClientConn) sendWorker(ctx context.Context, w net.Conn, r net.Conn) {
	var sp *gencode.SendPackets
	defer func() {
		if sp != nil {
			cc.bs.Put(sp)
		}
	}()
	for {
		if sp == nil {
			sp = cc.getSendPackets()
		}
		var err error
		sp.Packets, err = cc.writeBufferAndSend(ctx, sp.Packets, w, r)
		if err != nil && err != io.EOF {
			log.Printf("writeBufferAndSend err: %s", err)
			return
		}
		if len(sp.Packets) > 0 {
			if err := cc.postData(ctx, sp); err != nil {
				return
			}
			sp = nil
		}
		if err == io.EOF {
			return
		}
	}
}

func (cc *ClientConn) writeBufferAndSend(ctx context.Context, writeBuf []byte, w, r net.Conn) ([]byte, error) {
	if cap(writeBuf) < 4 {
		log.Printf("cap:%d", cap(writeBuf))
		writeBuf = make([]byte, cc.proxy.bufSize)
	}
	header := writeBuf[:4] //[]byte{0, 0, 0, 0}
	n, err := cc.readFull(ctx, r, header)
	if err != nil {
		if n == 0 && err == io.EOF {
			return writeBuf, err
		}
		return writeBuf, fmt.Errorf("packet ReadFull header err: %w n:%d", err, n)
	}

	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if length < 1 {
		return writeBuf, fmt.Errorf("invalid payload length %d", length)
	}
	//log.Printf("header:%v length:%d len(writeBuf):%d, cap(writeBuf):%d,writeBuf[:4]:%v", header, length, len(writeBuf), cap(writeBuf), writeBuf[:4])
	if cap(writeBuf) < 4+length {
		writeBuf = writeBuf[:cap(writeBuf)]
		writeBuf = append(writeBuf, make([]byte, length+4-cap(writeBuf))...)
	}
	//log.Printf("header:%v length:%d len(writeBuf):%d, cap(writeBuf):%d,writeBuf[:4]:%v", header, length, len(writeBuf), cap(writeBuf), writeBuf[:4])
	databuf := writeBuf[4 : length+4]
	if n, err := cc.readFull(ctx, r, databuf); err != nil {
		return writeBuf, fmt.Errorf("packet ReadFull data err: %w n:%d want:%d", err, n, len(databuf))
	}
	if n, err := w.Write(writeBuf[:length+4]); err != nil {
		return writeBuf, fmt.Errorf("netWrite err: %w n:%d", err, n)
	}
	return writeBuf[:length+4], nil
}

func (cc *ClientConn) readFull(ctx context.Context, r net.Conn, buf []byte) (int, error) {
	size := 0
	for {
		if err := r.SetReadDeadline(time.Now().Add(cc.proxy.cfg.BufferFlushTime)); err != nil {
			return 0, err
		}
		nn, err := r.Read(buf)
		size += nn
		switch {
		case err == nil:
		case os.IsTimeout(err):
			select {
			case <-ctx.Done():
				return size, nil
			default:
			}
		case errors.Is(err, io.EOF):
			if size == 0 {
				return size, err
			}
			return size, io.ErrUnexpectedEOF
		case err != nil:
			log.Printf("read err:%s", err)
			return size, err
		}
		buf = buf[nn:]
		if len(buf) == 0 {
			return size, nil
		}
	}
}
