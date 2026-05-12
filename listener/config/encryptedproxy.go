package config

import (
	"encoding/json"
)

type EncryptedProxyServer struct {
	Enable   bool   `yaml:"enable" json:"enable"`
	Listen   string `yaml:"listen" json:"listen"`
	Password string `yaml:"password" json:"password"`
	Obfs     bool   `yaml:"obfs,omitempty" json:"obfs,omitempty"`
}

func (e EncryptedProxyServer) String() string {
	b, _ := json.Marshal(e)
	return string(b)
}
