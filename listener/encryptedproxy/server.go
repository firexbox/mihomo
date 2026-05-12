package encryptedproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/transport/socks5"
)

// ─── 常量 ────────────────────────────────────────────────────────────────────

const (
	epNonceSize       = 12
	epTagSize         = 16
	epFrameHeaderSize = 2
	epMaxPaddingSize  = 255
)

const (
	epAddrTypeIPv4   = 0x01
	epAddrTypeDomain = 0x03
	epAddrTypeIPv6   = 0x04
)

// ─── Listener ─────────────────────────────────────────────────────────────────

type Listener struct {
	closed    bool
	config    LC.EncryptedProxyServer
	listeners []net.Listener
	key       []byte
	obfKey    []byte
	handler   *sing.ListenerHandler
}

func New(config LC.EncryptedProxyServer, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-ENCRYPTED-PROXY"),
			inbound.WithSpecialRules(""),
		}
	}

	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.ENCRYPTEDPROXY,
		Additions: additions,
	})
	if err != nil {
		return nil, err
	}

	key := deriveEPKey(config.Password)
	var obfKey []byte
	if config.Obfs {
		obfKey = deriveEPObfuscationKey(key)
	}

	sl = &Listener{
		config:  config,
		key:     key,
		obfKey:  obfKey,
		handler: h,
	}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr
		l, err := inbound.Listen("tcp", addr)
		if err != nil {
			_ = sl.Close()
			return nil, err
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					if sl.closed {
						break
					}
					continue
				}

				if tcpConn, ok := c.(*net.TCPConn); ok {
					tcpConn.SetNoDelay(true)
				}

				go sl.HandleConn(c, additions...)
			}
		}()
	}

	return sl, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, lis := range l.listeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() string {
	return l.config.String()
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	return
}

// HandleConn 处理加密代理入站连接。
//
// 协议流程:
//  1. 读取 12 字节 nonce（可选反混淆）
//  2. 派生 AES-256-GCM 密钥
//  3. 在加密隧道内读取目标地址
//  4. 转发到 tunnel
func (l *Listener) HandleConn(conn net.Conn, additions ...inbound.Addition) {
	defer conn.Close()

	// 1. 读取 nonce
	rawNonce := make([]byte, epNonceSize)
	if _, err := io.ReadFull(conn, rawNonce); err != nil {
		return
	}

	// 2. 反混淆（如果启用）
	if l.obfKey != nil {
		epXorNonce(rawNonce, l.obfKey)
	}

	// 3. 提取 nonceBase（前 8 字节）
	nonceBase := make([]byte, 8)
	copy(nonceBase, rawNonce[:8])

	// 4. 创建 AES-256-GCM cipher
	block, err := aes.NewCipher(l.key)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	// 5. 创建加密连接
	epConn := &epCryptoConn{
		rawConn:      conn,
		gcm:          gcm,
		nonceBase:    nonceBase,
		obfsEnabled:  l.obfKey != nil,
		readCounter:  0,          // 服务端读 = 客户端写（counter 0..）
		writeCounter: 0x80000000, // 服务端写 = 客户端读（counter 0x80000000..）
	}

	// 6. 读取目标地址
	host, port, err := epDecodeAddr(epConn)
	if err != nil {
		return
	}

	// 7. 构造目标地址并转发
	target := socks5.ParseAddr(fmt.Sprintf("%s:%d", host, port))
	l.handler.HandleSocket(target, epConn, additions...)
}

// ─── 地址解码 ─────────────────────────────────────────────────────────────────

// epDecodeAddr 从加密隧道内读取 [addrType][addr][port]。
func epDecodeAddr(r io.Reader) (host string, port int, err error) {
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return "", 0, fmt.Errorf("读取地址类型失败: %w", err)
	}

	var hostBytes []byte
	switch typeBuf[0] {
	case epAddrTypeIPv4:
		hostBytes = make([]byte, 4)
		if _, err := io.ReadFull(r, hostBytes); err != nil {
			return "", 0, fmt.Errorf("读取 IPv4 地址失败: %w", err)
		}
		host = net.IP(hostBytes).String()

	case epAddrTypeDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return "", 0, fmt.Errorf("读取域名长度失败: %w", err)
		}
		domainLen := int(lenBuf[0])
		hostBytes = make([]byte, domainLen)
		if _, err := io.ReadFull(r, hostBytes); err != nil {
			return "", 0, fmt.Errorf("读取域名失败: %w", err)
		}
		host = string(hostBytes)

	case epAddrTypeIPv6:
		hostBytes = make([]byte, 16)
		if _, err := io.ReadFull(r, hostBytes); err != nil {
			return "", 0, fmt.Errorf("读取 IPv6 地址失败: %w", err)
		}
		host = net.IP(hostBytes).String()

	default:
		return "", 0, fmt.Errorf("未知地址类型: %d", typeBuf[0])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return "", 0, fmt.Errorf("读取端口失败: %w", err)
	}
	port = int(binary.BigEndian.Uint16(portBuf[:]))

	return host, port, nil
}

// ─── 密钥派生 ─────────────────────────────────────────────────────────────────

func deriveEPKey(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return h[:]
}

func deriveEPObfuscationKey(key []byte) []byte {
	h := sha256.Sum256(append([]byte("encrypted-proxy-nonce-obfs-v1"), key...))
	return h[:]
}

func epXorNonce(nonce, obfKey []byte) {
	for i := range nonce {
		nonce[i] ^= obfKey[i]
	}
}

// ─── 加密连接（服务端侧）─────────────────────────────────────────────────────

type epCryptoConn struct {
	rawConn      net.Conn
	gcm          cipher.AEAD
	nonceBase    []byte
	obfsEnabled  bool
	readCounter  uint32
	writeCounter uint32
	readBuf      bytesBuffer
	readMu       sync.Mutex
	writeMu      sync.Mutex
}

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

func (c *epCryptoConn) Close() error                        { return c.rawConn.Close() }
func (c *epCryptoConn) LocalAddr() net.Addr                { return c.rawConn.LocalAddr() }
func (c *epCryptoConn) RemoteAddr() net.Addr               { return c.rawConn.RemoteAddr() }
func (c *epCryptoConn) SetDeadline(t time.Time) error      { return c.rawConn.SetDeadline(t) }
func (c *epCryptoConn) SetReadDeadline(t time.Time) error  { return c.rawConn.SetReadDeadline(t) }
func (c *epCryptoConn) SetWriteDeadline(t time.Time) error { return c.rawConn.SetWriteDeadline(t) }

var _ net.Conn = (*epCryptoConn)(nil)

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

func epWriteObfsFrame(w io.Writer, payload []byte) error {
	// 服务端不添加随机填充 — 保持简洁
	padLen := 0
	totalLen := 1 + padLen + len(payload)

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(totalLen))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write([]byte{byte(padLen)}); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
