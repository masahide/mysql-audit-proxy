package mysql

import (
	"bytes"
	"encoding/binary"
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

	"github.com/masahide/mysql-audit-proxy/pkg/parser"
	"github.com/siddontang/mixer/mysql"
)

const (
	defaultMySQLPort      = "3306"
	defaultMySQLProxyPort = "9696"
)

// nolint:gochecknoglobals
var defaultCapability uint32 = mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_LONG_FLAG |
	mysql.CLIENT_CONNECT_WITH_DB | mysql.CLIENT_PROTOCOL_41 |
	mysql.CLIENT_TRANSACTIONS | mysql.CLIENT_SECURE_CONNECTION

// Config Proxy
type Config struct {
	Net            string `yaml:"net"`
	Addr           string `yaml:"addr"`
	AllowIps       string `yaml:"allow_ips"`
	CaCertFile     string
	CaKeyFile      string
	ClientCertFile string
	ClientKeyFile  string
	ConfigPath     string
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
	running  bool
	listener net.Listener
	allowips []net.IP
	//node     *NodeConfig
	baseConnID uint32
}

// NewServer new Server
func NewServer(cfg *Config) (*Server, error) {
	s := new(Server)

	s.cfg = cfg

	s.addr = cfg.Addr

	s.parseAllowIps()

	s.baseConnID = 10000
	var err error

	s.listener, err = net.Listen(cfg.Net, s.addr)

	if err != nil {
		return nil, err
	}

	if cfg.Net == "unix" {
		if err = os.Chmod(s.addr, 0777); err != nil {
			return nil, err
		}
	}

	log.Printf("server.NewServer Server running. address %s:%s", cfg.Net, s.addr)
	return s, nil
}

func (s *Server) newClientConn(conn net.Conn) *ClientConn {
	c := new(ClientConn)
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
		c.c = tcpConn
	default:
		c.c = conn
	}

	c.pkg = mysql.NewPacketIO(c.c)
	c.proxy = s

	c.pkg.Sequence = 0

	c.connectionID = atomic.AddUint32(&s.baseConnID, 1)

	c.status = mysql.SERVER_STATUS_AUTOCOMMIT

	c.salt = mysql.RandomBuf(20)

	c.closed = false

	//c.collation = mysql.DEFAULT_COLLATION_ID
	//c.charset = mysql.DEFAULT_CHARSET

	return c
}

func (s *Server) onConn(c net.Conn) {
	clConn := s.newClientConn(c)

	defer func() {
		err := recover()
		if err != nil {
			buf := make([]byte, 4096)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("Error server.onConn remoteAddr:%s, stack:%s", c.RemoteAddr().String(), string(buf))
		}

		clConn.close()
	}()

	if allowConnect := clConn.isAllowConnect(); allowConnect {
		err := mysql.NewError(mysql.ER_ACCESS_DENIED_ERROR, "ip address access denied by mysqlproxy.")
		if err := clConn.writeError(err); err != nil {
			log.Printf("onConn.writeError:%s", err)
		}
		clConn.close()
		return
	}
	if err := clConn.handshake(); err != nil {
		log.Printf("Error server.onConn  %s", err.Error())
		c.Close()
		return
	}

	clConn.run()
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
func (s *Server) Run() error {
	s.running = true

	for s.running {
		aConn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Error server.Run %s", err.Error())
			continue
		}

		go s.onConn(aConn)
	}

	return nil
}

// Close server
func (s *Server) Close() {
	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}
}

//ClientConn client <-> proxy
type ClientConn struct {
	pkg          *mysql.PacketIO
	c            net.Conn
	proxy        *Server
	capability   uint32
	connectionID uint32
	status       uint16
	//collation    mysql.CollationId
	//charset      string
	user   string
	db     string
	salt   []byte
	closed bool
	//lastInsertId int64
	//affectedRows int64
	node *NodeConfig
}

func (c *ClientConn) close() error {
	if c.closed {
		return nil
	}

	if err := c.c.Close(); err != nil {
		return err
	}

	c.closed = true

	return nil
}
func (c *ClientConn) isAllowConnect() bool {
	clientHost, _, err := net.SplitHostPort(c.c.RemoteAddr().String())
	if err != nil {
		fmt.Println(err)
	}
	clientIP := net.ParseIP(clientHost)

	ipVec := c.proxy.allowips
	if ipVecLen := len(ipVec); ipVecLen == 0 {
		return true
	}
	for _, ip := range ipVec {
		if ip.Equal(clientIP) {
			return true
		}
	}

	log.Printf("Error server.isAllowConnect [Access denied]. address:%s ", c.c.RemoteAddr().String())
	return false
}
func (c *ClientConn) writeError(e error) error {
	var m *mysql.SqlError
	var ok bool
	if m, ok = e.(*mysql.SqlError); !ok {
		m = mysql.NewError(mysql.ER_UNKNOWN_ERROR, e.Error())
	}

	data := make([]byte, 4, 16+len(m.Message))

	data = append(data, mysql.ERR_HEADER)
	data = append(data, byte(m.Code), byte(m.Code>>8))

	if c.capability&mysql.CLIENT_PROTOCOL_41 > 0 {
		data = append(data, '#')
		data = append(data, m.State...)
	}

	data = append(data, m.Message...)

	return c.writePacket(data)
}
func (c *ClientConn) handshake() error {
	if err := c.writeInitialHandshake(); err != nil {
		log.Printf("Error server.handshake  [%s] connectionID:%d", err.Error(), c.connectionID)
		return err
	}

	if err := c.readHandshakeResponse(); err != nil {
		log.Printf("Error server.readHandshakeResponse [%s] connectionID:%d", err.Error(), c.connectionID)

		if err := c.writeError(err); err != nil {
			log.Printf("handshake.writeError:%s", err)
		}

		return err
	}

	if err := c.writeOK(nil); err != nil {
		log.Printf("Error server.readHandshakeResponse [write ok fail] [%s] connectionID:%d", err.Error(), c.connectionID)
		return err
	}

	c.pkg.Sequence = 0

	return nil
}
func (c *ClientConn) writeOK(r *mysql.Result) error {
	if r == nil {
		r = &mysql.Result{Status: c.status}
	}
	data := make([]byte, 4, 32)

	data = append(data, mysql.OK_HEADER)

	data = append(data, mysql.PutLengthEncodedInt(r.AffectedRows)...)
	data = append(data, mysql.PutLengthEncodedInt(r.InsertId)...)

	if c.capability&mysql.CLIENT_PROTOCOL_41 > 0 {
		data = append(data, byte(r.Status), byte(r.Status>>8))
		data = append(data, 0, 0)
	}

	return c.writePacket(data)
}

func (c *ClientConn) writeInitialHandshake() error {
	data := make([]byte, 4, 128)

	//min version 10
	data = append(data, 10)

	//server version[00]
	data = append(data, mysql.ServerVersion...)
	data = append(data, 0)

	//connection id
	data = append(data, byte(c.connectionID), byte(c.connectionID>>8), byte(c.connectionID>>16), byte(c.connectionID>>24))

	//auth-plugin-data-part-1
	data = append(data, c.salt[0:8]...)

	//filter [00]
	data = append(data, 0)

	//capability flag lower 2 bytes, using default capability here
	data = append(data, byte(defaultCapability), byte(defaultCapability>>8))

	//charset, utf-8 default
	data = append(data, uint8(mysql.DEFAULT_COLLATION_ID))

	//status
	data = append(data, byte(c.status), byte(c.status>>8))

	//below 13 byte may not be used
	//capability flag upper 2 bytes, using default capability here
	data = append(data, byte(defaultCapability>>16), byte(defaultCapability>>24))

	//filter [0x15], for wireshark dump, value is 0x15
	data = append(data, 0x15)

	//reserved 10 [00]
	data = append(data, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

	//auth-plugin-data-part-2
	data = append(data, c.salt[8:]...)

	//filter [00]
	data = append(data, 0)

	return c.writePacket(data)
}

func (c *ClientConn) getNodeFromConfigFile() (*NodeConfig, error) {
	if c.proxy.cfg.ConfigPath == "" {
		return nil, nil
	}
	if strings.Contains(c.user, ";") {
		return nil, nil
	}
	p := parser.Parser{
		ConfigPath: c.proxy.cfg.ConfigPath,
	}
	proxyUsers, err := p.Parse()
	if err != nil {
		return nil, err
	}
	substrings := strings.Split(c.user, "@")
	if len(substrings) != 2 {
		return nil, fmt.Errorf("invalid user: %s", c.user)
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
var nodeRe = regexp.MustCompile(`^(.+):(.*)@(.+:\d+);(.+:\d+)(;(.+))?$`)

// getNode parse from c.user
// example: user:pass@proxy_host:proxy_port;db_host:db_port;db_name
// pass and db_name is optional
// example: user:@proxy_host:proxy_port;db_host:db_port
func (c *ClientConn) getNode() error {
	var err error
	if c.node, err = c.getNodeFromConfigFile(); err != nil {
		log.Print(err)
	}
	if c.node != nil {
		return nil
	}
	matches := nodeRe.FindStringSubmatch(c.user)
	if len(matches) != 7 {
		return fmt.Errorf("invalid user: %s", c.user)
	}
	c.node = &NodeConfig{
		User:     matches[1],
		Password: matches[2],
		Db:       matches[6],
		Addr:     matches[4],
	}
	return nil
}
func (c *ClientConn) readHandshakeResponse() error {
	data, err := c.readPacket()

	if err != nil {
		return err
	}

	pos := 0

	//capability
	c.capability = binary.LittleEndian.Uint32(data[:4])
	pos += 4

	//skip max packet size
	pos += 4

	//charset, skip, if you want to use another charset, use set names
	//c.collation = CollationId(data[pos])
	pos++

	//skip reserved 23[00]
	pos += 23

	//user name
	c.user = string(data[pos : pos+bytes.IndexByte(data[pos:], 0)])
	if err := c.getNode(); err != nil {
		return err
	}
	pos += len(c.user) + 1

	//auth length and auth
	authLen := int(data[pos])
	pos++
	auth := data[pos : pos+authLen]

	checkAuth := mysql.CalcPassword(c.salt, []byte(c.node.Password))
	if !bytes.Equal(auth, checkAuth) {
		log.Printf("Error ClientConn.readHandshakeResponse. auth:%v, checkAuth:%v, Password:%v",
			auth, checkAuth, c.node.Password)
		return mysql.NewDefaultError(mysql.ER_ACCESS_DENIED_ERROR, c.c.RemoteAddr().String(), c.user, "Yes")
	}

	pos += authLen

	if c.capability&mysql.CLIENT_CONNECT_WITH_DB > 0 {
		if len(data[pos:]) == 0 {
			return nil
		}

		db := string(data[pos : pos+bytes.IndexByte(data[pos:], 0)])
		//pos += len(c.db) + 1

		if err := c.useDB(db); err != nil {
			return err
		}
	}

	return nil
}
func (c *ClientConn) useDB(db string) error {
	c.db = db
	c.node.Db = db
	return nil
}

func (c *ClientConn) readPacket() ([]byte, error) {
	return c.pkg.ReadPacket()
}

func (c *ClientConn) writePacket(data []byte) error {
	return c.pkg.WritePacket(data)
}

func (c *ClientConn) run() {
	defer func() {
		r := recover()
		if err, ok := r.(error); ok {
			buf := make([]byte, 4096)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("Error ClientConn.Run [%s] stak:%s", err.Error(), string(buf))
		}

		c.close()
	}()

	log.Printf("Success Handshake. RemoteAddr:%s", c.c.RemoteAddr())
	pc := new(ProxyClient)
	pc.client = c
	db := c.node
	if err := pc.connect(db.Addr, db.User, db.Password, db.Db); err != nil {
		log.Fatal(err)
	}
	log.Printf("Success Connect. RemoteAddr:%s", pc.conn.RemoteAddr())

	done := make(chan bool)
	var once sync.Once
	onceDone := func() {
		log.Printf("done.")
		done <- true
	}
	go func() {
		// nolint:errcheck
		io.Copy(c.c, pc.conn)
		once.Do(onceDone)
	}()
	go func() {
		// nolint:errcheck
		io.Copy(pc.conn, c.c)
		once.Do(onceDone)
	}()
	<-done
}
