// Package nodekey
//
// @author: xwc1125
package nodekey

import (
	"crypto"
	"crypto/sha256"
	"github.com/chain5j/chain5j-pkg/crypto/signature"
	pcrypto "github.com/chain5j/chain5j-protocol/pkg/crypto"
	"github.com/chain5j/chain5j-protocol/protocol"
	"hash"
)

var (
	_ protocol.PubKey = new(PublicKey)
)

// PublicKey 公钥，实现p2p的公钥接口
type PublicKey struct {
	cryptoType pcrypto.CryptoType
	pub        crypto.PublicKey
}

// NewPublicKey 原生公钥转自有公钥
func NewPublicKey(pub crypto.PublicKey) (*PublicKey, error) {
	return ToPublicKey(pub)
}

func (ePub *PublicKey) Marshal() ([]byte, error) {
	jsonKey, err := MarshalPublicKey(ePub)
	if err != nil {
		log().Error("marshal public key err", "err", err)
		return nil, err
	}
	return jsonKey.Serialize()
}
func (ePub *PublicKey) Unmarshal(input []byte) error {
	key, err := UnmarshalPublicKey(input)
	if err != nil {
		log().Error("unmarshal public key err", "err", err)
		return err
	}
	*ePub = *key
	return nil
}
func (ePub *PublicKey) Equals(key protocol.Key) bool {
	return pcrypto.BasicEquals(ePub, key)
}
func (ePub *PublicKey) Type() protocol.KeyType {
	return protocol.KeyType(ePub.cryptoType.KeyType)
}

// Raw x509格式，否则libp2p会报错
func (ePub *PublicKey) Raw() ([]byte, error) {
	jsonKey, err := MarshalPublicKeyX509(ePub.pub)
	if err != nil {
		log().Error("publicKey to Raw: marshalPublicKey err", "err", err)
		return nil, err
	}
	// 对于已经是x509的直接返回jsonKey.Data，其他的返回jsonKey.Serialize()
	switch ePub.cryptoType {
	case pcrypto.RSA, pcrypto.P256, pcrypto.P384, pcrypto.P521:
		return jsonKey.Data, nil
	}
	return jsonKey.Serialize()
}
func (ePub *PublicKey) Hash() func() hash.Hash {
	return ePub.getHash()
}

// Verify 验证签名
func (ePub *PublicKey) Verify(data []byte, signResult *signature.SignResult) (bool, error) {
	return Verify(data, signResult)
}

func (ePub *PublicKey) getHash() func() hash.Hash {
	switch ePub.cryptoType {
	case pcrypto.RSA:
		return sha256.New
	case pcrypto.Ed25519:
		return sha256.New
	default:
		return signature.HashFunc(ePub.cryptoType.KeyName)
	}
}
