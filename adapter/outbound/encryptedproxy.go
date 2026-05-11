package outbound

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// ─── EncryptedProxy 出站协议 ─────────────────────────────────────────────────
//
// 将 encrypted-proxy (AES-256-GCM + 可选混淆) 作为 mihomo 原生出站协议。
//
// 协议流程:
//   1. TCP Dial → 远程加密代理服务端
//   2. 发送随机 nonce（可选 XOR 混淆）
//   3. 建立 AES-256-GCM 加密隧道
//   4. 每条连接在隧道内发送 [addrType 1B][addrLen 1B][addr][port 2B] 协议头
//   5. 双向数据中继
//
// 混淆（-obfs）: Nonce XOR + 帧填充 + 可选时序抖动
//
// YAML 配置示例:
//   proxies:
//     - name: "ep-server"
//       type: encrypted-proxy
//       server: so1.firedragon18.top
//       port: 8388
//       password: "mypassword"
//       obfs: true
//       pool-size: 5

// ─── 常量 ────────────────────────────────────────────────────────────────────

const (
	epNonceSize       = 12
	epTagSize         = 16
	epFrameHeaderSize = 2
	epMaxFrameSize    = 65535
	epMaxPaddingSize  = 255
	epMaxPlainSize    = epMaxFrameSize - epTagSize - 1 - epMaxPaddingSize
	epJitterMaxMicros = 50000
	epDefaultPoolSize = 5
	epMaxPoolSize     = 32
	epPoolDialTimeout = 5 * time.Second
)

const (
	epAddrTypeIPv4   = 0x01
	epAddrTypeDomain = 0x03
	epAddrTypeIPv6   = 0x04
)

// ─── 配置结构体 ──────────────────────────────────────────────────────────────

type EncryptedProxyOption struct {
	BasicOption
	Name     string `proxy:"name"`
	Server   string `proxy:"server"`
	Port     int    `proxy:"port"`
	Password string `proxy:"password"`
	Obfs     bool   `proxy:"obfs,omitempty"`
	Jitter   bool   `proxy:"jitter,omitempty"`
	PoolSize int    `proxy:"pool-size,omitempty"`
}

// ─── 出站适配器 ──────────────────────────────────────────────────────────────

type EncryptedProxy struct {
	*Base
	option   *EncryptedProxyOption
	key      []byte
	obfKey   []byte
	pool     *epConnPool
}

// ─── 连接池 ──────────────────────────────────────────────────────────────────

type epConnPool struct {
	remoteAddr string
	key        []byte
	obfs       bool
	jitter     bool
	dialer     C.Dialer

	ch     chan *epCryptoConn
	size   int
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func newEPConnPool(ep *EncryptedProxy) *epConnPool {
	size := ep.option.PoolSize
	if size <= 0 {
		size = epDefaultPoolSize
	}
	if size > epMaxPoolSize {
		size = epMaxPoolSize
	}

	p := &epConnPool{
		remoteAddr: net.JoinHostPort(ep.option.Server, strconv.Itoa(ep.option.Port)),
		key:        ep.key,
		obfs:       ep.option.Obfs,
		jitter:     ep.option.Jitter,
		dialer:     ep.dialer,
		ch:         make(chan *epCryptoConn, size),
		size:       size,
	}

	// 预热
	for i := 0; i < size; i++ {
		p.wg.Add(1)
		go p.warmUp()
	}

	return p
}

func (p *epConnPool) warmUp() {
	defer p.wg.Done()

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	conn, err := p.dial()
	if err != nil {
		return
	}

	p.mu.Lock()
	if p.closed {
		conn.rawConn.Close()
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	select {
	case p.ch <- conn:
	default:
		conn.rawConn.Close()
	}
}

func (p *epConnPool) dial() (*epCryptoConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), epPoolDialTimeout)
	defer cancel()

	rawConn, err := p.dialer.DialContext(ctx, "tcp", p.remoteAddr)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	cryptoConn, err := newEPClientConn(rawConn, p.key, p.obfs, p.jitter)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	return cryptoConn, nil
}

func (p *epConnPool) Get() (*epCryptoConn, error) {
	select {
	case conn := <-p.ch:
		// 异步补充
		p.mu.Lock()
		if !p.closed {
			p.wg.Add(1)
			go p.warmUp()
		}
		p.mu.Unlock()
		return conn, nil
	default:
		// 池空，新建
		c, err := p.dial()

		p.mu.Lock()
		if !p.closed {
			p.wg.Add(1)
			go p.warmUp()
		}
		p.mu.Unlock()

		return c, err
	}
}

func (p *epConnPool) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()

	p.wg.Wait()
	close(p.ch)
	for conn := range p.ch {
		conn.rawConn.Close()
	}
}

// ─── 加密连接 ────────────────────────────────────────────────────────────────

type epCryptoConn struct {
	rawConn       net.Conn
	gcm           cipher.AEAD
	nonceBase     []byte
	obfKey        []byte
	obfsEnabled   bool
	jitterEnabled bool
	readCounter   uint32
	writeCounter  uint32
	readBuf       bytesBuffer
	readMu        sync.Mutex
	writeMu       sync.Mutex
}

// bytesBuffer — 简化版 bytes.Buffer 避免导包
type bytesBuffer struct {
	buf []byte
}

func (b *bytesBuffer) Len() int { return len(b.buf) }

func (b *bytesBuffer) Read(p []byte) (int, error) {
	if len(b.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	return n, nil
}

func (b *bytesBuffer) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}

// newEPClientConn 作为加密代理客户端，生成随机 nonce 并发送给服务端。
func newEPClientConn(rawConn net.Conn, key []byte, obfsEnabled, jitterEnabled bool) (*epCryptoConn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 生成 12 字节随机 nonce
	rawNonce := make([]byte, epNonceSize)
	if _, err := io.ReadFull(rand.Reader, rawNonce); err != nil {
		return nil, fmt.Errorf("生成 nonce 失败: %w", err)
	}

	nonceBase := make([]byte, 8)
	copy(nonceBase, rawNonce[:8])

	var obfKey []byte
	sendNonce := rawNonce
	if obfsEnabled {
		obfKey = deriveEPObfuscationKey(key)
		obfsNonce := make([]byte, epNonceSize)
		copy(obfsNonce, rawNonce)
		epXorNonce(obfsNonce, obfKey)
		sendNonce = obfsNonce
	}

	if _, err := rawConn.Write(sendNonce); err != nil {
		return nil, fmt.Errorf("发送 nonce 失败: %w", err)
	}

	return &epCryptoConn{
		rawConn:       rawConn,
		gcm:           gcm,
		nonceBase:     nonceBase,
		obfKey:        obfKey,
		obfsEnabled:   obfsEnabled,
		jitterEnabled: jitterEnabled,
		writeCounter:  0,
		readCounter:   0x80000000,
	}, nil
}

// deriveEPKey — SHA256 密钥派生
func deriveEPKey(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return h[:]
}

// deriveEPObfuscationKey — 派生混淆密钥
func deriveEPObfuscationKey(key []byte) []byte {
	h := sha256.Sum256(append([]byte("encrypted-proxy-nonce-obfs-v1"), key...))
	return h[:]
}

func epXorNonce(nonce, obfKey []byte) {
	for i := range nonce {
		nonce[i] ^= obfKey[i]
	}
}

func (c *epCryptoConn) makeNonce(counter uint32) []byte {
	n := make([]byte, epNonceSize)
	copy(n[:8], c.nonceBase)
	binary.BigEndian.PutUint32(n[8:], counter)
	return n
}

func (c *epCryptoConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}

	var frame []byte
	var err error
	if c.obfsEnabled {
		frame, err = epReadObfsFrame(c.rawConn)
	} else {
		frame, err = epReadRawFrame(c.rawConn)
	}
	if err != nil {
		return 0, err
	}

	nonce := c.makeNonce(c.readCounter)
	c.readCounter++

	plaintext, err := c.gcm.Open(nil, nonce, frame, nil)
	if err != nil {
		return 0, fmt.Errorf("解密失败: %w", err)
	}

	c.readBuf.Write(plaintext)
	return c.readBuf.Read(p)
}

func (c *epCryptoConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if len(p) > epMaxPlainSize {
		// 分片写入
		return c.chunkedWriteInternal(p)
	}

	if c.jitterEnabled {
		epRandomJitter(epJitterMaxMicros)
	}

	nonce := c.makeNonce(c.writeCounter)
	c.writeCounter++

	sealed := c.gcm.Seal(nil, nonce, p, nil)

	var err error
	if c.obfsEnabled {
		err = epWriteObfsFrame(c.rawConn, sealed)
	} else {
		err = epWriteRawFrame(c.rawConn, sealed)
	}
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *epCryptoConn) chunkedWriteInternal(data []byte) (int, error) {
	total := 0
	for len(data) > 0 {
		chunk := data
		if len(chunk) > epMaxPlainSize {
			chunk = chunk[:epMaxPlainSize]
		}

		if c.jitterEnabled {
			epRandomJitter(epJitterMaxMicros)
		}

		nonce := c.makeNonce(c.writeCounter)
		c.writeCounter++

		sealed := c.gcm.Seal(nil, nonce, chunk, nil)

		var err error
		if c.obfsEnabled {
			err = epWriteObfsFrame(c.rawConn, sealed)
		} else {
			err = epWriteRawFrame(c.rawConn, sealed)
		}
		if err != nil {
			return total, err
		}

		total += len(chunk)
		data = data[len(chunk):]
	}
	return total, nil
}

func (c *epCryptoConn) Close() error                        { return c.rawConn.Close() }
func (c *epCryptoConn) LocalAddr() net.Addr                { return c.rawConn.LocalAddr() }
func (c *epCryptoConn) RemoteAddr() net.Addr               { return c.rawConn.RemoteAddr() }
func (c *epCryptoConn) SetDeadline(t time.Time) error      { return c.rawConn.SetDeadline(t) }
func (c *epCryptoConn) SetReadDeadline(t time.Time) error  { return c.rawConn.SetReadDeadline(t) }
func (c *epCryptoConn) SetWriteDeadline(t time.Time) error { return c.rawConn.SetWriteDeadline(t) }

var _ net.Conn = (*epCryptoConn)(nil)

// ─── 协议地址编码 ────────────────────────────────────────────────────────────

// epEncodeAddr 在加密隧道内发送目标地址。
func epEncodeAddr(w io.Writer, host string, port int) error {
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf := make([]byte, 1+4+2)
			buf[0] = epAddrTypeIPv4
			copy(buf[1:5], ip4)
			binary.BigEndian.PutUint16(buf[5:7], uint16(port))
			_, err := w.Write(buf)
			return err
		}
		buf := make([]byte, 1+16+2)
		buf[0] = epAddrTypeIPv6
		copy(buf[1:17], ip.To16())
		binary.BigEndian.PutUint16(buf[17:19], uint16(port))
		_, err := w.Write(buf)
		return err
	}

	domain := host
	if len(domain) > 255 {
		return fmt.Errorf("域名过长: %d 字节", len(domain))
	}
	buf := make([]byte, 1+1+len(domain)+2)
	buf[0] = epAddrTypeDomain
	buf[1] = byte(len(domain))
	copy(buf[2:2+len(domain)], domain)
	binary.BigEndian.PutUint16(buf[2+len(domain):2+len(domain)+2], uint16(port))
	_, err := w.Write(buf)
	return err
}

// ─── 帧 I/O ──────────────────────────────────────────────────────────────────

func epReadRawFrame(r io.Reader) ([]byte, error) {
	var lenBuf [epFrameHeaderSize]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	frameLen := binary.BigEndian.Uint16(lenBuf[:])
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

func epWriteRawFrame(w io.Writer, payload []byte) error {
	var lenBuf [epFrameHeaderSize]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func epWriteObfsFrame(w io.Writer, payload []byte) error {
	padLen := epRandomPaddingSize()
	totalLen := 1 + padLen + len(payload)

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(totalLen))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}

	if _, err := w.Write([]byte{byte(padLen)}); err != nil {
		return err
	}

	if padLen > 0 {
		pad := make([]byte, padLen)
		if _, err := io.ReadFull(rand.Reader, pad); err != nil {
			return err
		}
		if _, err := w.Write(pad); err != nil {
			return err
		}
	}

	_, err := w.Write(payload)
	return err
}

func epReadObfsFrame(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	totalLen := binary.BigEndian.Uint16(lenBuf[:])

	var padLenBuf [1]byte
	if _, err := io.ReadFull(r, padLenBuf[:]); err != nil {
		return nil, err
	}
	padLen := int(padLenBuf[0])

	if padLen > 0 {
		pad := make([]byte, padLen)
		if _, err := io.ReadFull(r, pad); err != nil {
			return nil, err
		}
	}

	payloadLen := int(totalLen) - 1 - padLen
	if payloadLen < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func epRandomPaddingSize() int {
	n, err := rand.Int(rand.Reader, big.NewInt(epMaxPaddingSize+1))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

func epRandomJitter(maxMicros int) {
	if maxMicros <= 0 {
		return
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxMicros+1)))
	if err != nil {
		return
	}
	time.Sleep(time.Duration(n.Int64()) * time.Microsecond)
}

// ─── mihomo ProxyAdapter 接口实现 ────────────────────────────────────────────

// DialContext 建立加密连接并发送目标地址头。
func (ep *EncryptedProxy) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	cryptoConn, err := ep.pool.Get()
	if err != nil {
		return nil, fmt.Errorf("%s 连接加密代理失败: %w", ep.addr, err)
	}

	defer func() {
		if err != nil {
			cryptoConn.Close()
		}
	}()

	// 在加密隧道内发送目标地址
	host := metadata.Host
	port := int(metadata.DstPort)
	if port == 0 {
		port = 443
	}
	if host == "" {
		host = metadata.DstIP.String()
	}

	if err := epEncodeAddr(cryptoConn, host, port); err != nil {
		return nil, fmt.Errorf("发送协议头失败: %w", err)
	}

	return NewConn(cryptoConn, ep), nil
}

// ProxyInfo implements C.ProxyAdapter
func (ep *EncryptedProxy) ProxyInfo() C.ProxyInfo {
	info := ep.Base.ProxyInfo()
	info.DialerProxy = ep.option.DialerProxy
	return info
}

func (ep *EncryptedProxy) Close() error {
	if ep.pool != nil {
		ep.pool.Close()
	}
	return nil
}

// ─── 构造函数 ────────────────────────────────────────────────────────────────

func NewEncryptedProxy(option EncryptedProxyOption) (*EncryptedProxy, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	key := deriveEPKey(option.Password)

	outbound := &EncryptedProxy{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.EncryptedProxy,
			ProviderName: option.ProviderName,
			UDP:          false,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
		key:    key,
	}

	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.pool = newEPConnPool(outbound)

	return outbound, nil
}

// 确保接口实现
var _ ProxyAdapter = (*EncryptedProxy)(nil)
