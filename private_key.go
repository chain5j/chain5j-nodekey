// Package nodekey
//
// @author: xwc1125
package nodekey

import (
	"crypto"
	"github.com/chain5j/chain5j-pkg/crypto/signature"
	"github.com/chain5j/chain5j-protocol/models"
	pcrypto "github.com/chain5j/chain5j-protocol/pkg/crypto"
	"github.com/chain5j/chain5j-protocol/protocol"
	"hash"
)

var (
	_ protocol.PrivKey = new(PrivateKey)
)

// PrivateKey 私钥，实现p2p的私钥接口
type PrivateKey struct {
	cryptoType pcrypto.CryptoType
	prv        crypto.PrivateKey
	publicKey  *PublicKey
}

// NewPrivateKey 根据原生私钥创建一个自有私钥
func NewPrivateKey(prv crypto.PrivateKey) (*PrivateKey, error) {
	return ToPrivateKey(prv)
}

func (p *PrivateKey) Marshal() ([]byte, error) {
	jsonKey, err := MarshalPrivateKey(p)
	if err != nil {
		log().Error("marshal private key err", "err", err)
		return nil, err
	}
	return jsonKey.Serialize()
}
func (p *PrivateKey) Unmarshal(input []byte) error {
	privateKey, err := UnmarshalPrivateKey(input)
	if err != nil {
		log().Error("unmarshal private key err", "err", err)
		return err
	}
	*p = *privateKey
	return nil
}
func (p *PrivateKey) Equals(key protocol.Key) bool {
	return pcrypto.BasicEquals(p, key)
}

// Raw x509格式，否则libp2p会报错
func (p *PrivateKey) Raw() ([]byte, error) {
	jsonKey, err := MarshalPrivateKeyX509(p.prv)
	if err != nil {
		log().Error("marshal private x509 err", "err", err)
		return nil, err
	}
	// 对于已经是x509的直接返回jsonKey.Data，其他的返回jsonKey.Serialize()
	switch p.cryptoType {
	case pcrypto.RSA, pcrypto.P256, pcrypto.P384, pcrypto.P521:
		return jsonKey.Data, nil
	}
	return jsonKey.Serialize()
}
func (p *PrivateKey) Type() protocol.KeyType {
	return protocol.KeyType(p.cryptoType.KeyType)
}
func (p *PrivateKey) Hash() func() hash.Hash {
	return p.publicKey.getHash()
}

// Sign 签名data
func (p *PrivateKey) Sign(data []byte) (*signature.SignResult, error) {
	signResult, err := Sign(data, p.prv)
	if err != nil {
		log().Error("sign data err", "err", err)
		return nil, err
	}
	return signResult, nil
}

// GetPublic 获取public
func (p *PrivateKey) GetPublic() protocol.PubKey {
	return p.publicKey
}

// ID 返回nodeId
func (p *PrivateKey) ID() (models.NodeID, error) {
	id, err := IDFromPrivateKey(p)
	if err != nil {
		log().Error("private key to nodeId err", "err", err)
		return "", err
	}

	return id, nil
}

func (p *PrivateKey) MarshalJSON() ([]byte, error) {
	jsonKey, err := MarshalPrivateKey(p.prv)
	if err != nil {
		log().Error("marshal private key err", "err", err)
		return nil, err
	}
	return jsonKey.Serialize()
}
func (p *PrivateKey) UnmarshalJSON(bytes []byte) error {
	privKey, err := UnmarshalPrivateKey(bytes)
	if err != nil {
		log().Error("unmarshal private key err", "err", err)
		return err
	}
	p.cryptoType = privKey.cryptoType
	p.prv = privKey.prv

	return nil
}
