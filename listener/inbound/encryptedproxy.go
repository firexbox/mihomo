package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/encryptedproxy"
	"github.com/metacubex/mihomo/log"
)

type EncryptedProxyOption struct {
	BaseOption
	Password string `inbound:"password"`
	Obfs     bool   `inbound:"obfs,omitempty"`
}

func (o EncryptedProxyOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type EncryptedProxy struct {
	*Base
	config *EncryptedProxyOption
	l      C.MultiAddrListener
	vs     LC.EncryptedProxyServer
}

func NewEncryptedProxy(options *EncryptedProxyOption) (*EncryptedProxy, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &EncryptedProxy{
		Base:   base,
		config: options,
		vs: LC.EncryptedProxyServer{
			Enable:   true,
			Listen:   base.RawAddress(),
			Password: options.Password,
			Obfs:     options.Obfs,
		},
	}, nil
}

// Config implements constant.InboundListener
func (v *EncryptedProxy) Config() C.InboundConfig {
	return v.config
}

// Address implements constant.InboundListener
func (v *EncryptedProxy) Address() string {
	var addrList []string
	if v.l != nil {
		for _, addr := range v.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (v *EncryptedProxy) Listen(tunnel C.Tunnel) error {
	var err error
	v.l, err = encryptedproxy.New(v.vs, tunnel, v.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("EncryptedProxy[%s] proxy listening at: %s", v.Name(), v.Address())
	return nil
}

// Close implements constant.InboundListener
func (v *EncryptedProxy) Close() error {
	return v.l.Close()
}

var _ C.InboundListener = (*EncryptedProxy)(nil)
