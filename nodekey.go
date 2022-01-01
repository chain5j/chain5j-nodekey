// Package nodekey
//
// @author: xwc1125
package nodekey

import (
	"context"
	"crypto"
	"errors"
	"github.com/chain5j/chain5j-pkg/crypto/signature"
	"github.com/chain5j/chain5j-protocol/models"
	pcrypto "github.com/chain5j/chain5j-protocol/pkg/crypto"
	"github.com/chain5j/chain5j-protocol/protocol"
	"github.com/chain5j/logger"
)

var (
	_              protocol.NodeKey = new(nodeKey)
	errInvalidPath                  = errors.New("invalid nodekey path")
)

const nodekeyFile = "nodekey"

// nodeKey 节点key
type nodeKey struct {
	log    logger.Logger
	config protocol.Config

	id models.NodeID // 节点ID

	prvKey *PrivateKey
	pubKey *PublicKey
}

// NewNodeKey 创建新的NodeKey
func NewNodeKey(rootCtx context.Context, opts ...option) (protocol.NodeKey, error) {
	n := &nodeKey{
		log: logger.New("nodeKey"),
	}
	if err := apply(n, opts...); err != nil {
		n.log.Error("apply is error", "err", err)
		return nil, err
	}

	nodeKeyConfig := n.config.NodeKeyConfig()
	fileType := nodeKeyConfig.FileType
	prvKeyFile := nodeKeyConfig.PrvKeyFile
	pubKeyFile := nodeKeyConfig.PubKeyFile
	pwd := nodeKeyConfig.Password

	var err error

	n.prvKey, err = LoadPrivateKey(FileType(fileType), prvKeyFile, pubKeyFile, pwd)
	if err != nil {
		n.log.Error("load private key err", "fileType", fileType, "prvKeyFile", prvKeyFile, "err", err)
		return nil, err
	}

	n.pubKey, err = NewPublicKey(n.prvKey.GetPublic())
	if err != nil {
		n.log.Error("newNodeKey with NewPublicKey err", "err", err)
		return nil, err
	}

	nodeId, err := n.ID()
	if err != nil {
		n.log.Error("key to nodeId err", "err", err)
		return nil, err
	}
	n.log.Info("nodeId", "nodeId", nodeId)

	return n, nil
}

// ID 获取nodeId
func (n *nodeKey) ID() (models.NodeID, error) {
	return n.prvKey.ID()
}

// IdFromPub 通过公钥获取ID
func (n *nodeKey) IdFromPub(pub crypto.PublicKey) (models.NodeID, error) {
	return IdFromPub(pub)
}

// PrvKey 获取原始私钥
func (n *nodeKey) PrvKey() crypto.PrivateKey {
	return n.prvKey.prv
}

// PubKey 获取p2p公钥
func (n *nodeKey) PubKey(pubKey crypto.PublicKey) (protocol.PubKey, error) {
	return ToPublicKey(pubKey)
}

// RecoverId 恢复节点ID
func (n *nodeKey) RecoverId(data []byte, signResult *signature.SignResult) (models.NodeID, error) {
	return RecoverId(data, signResult)
}

// RecoverPub 恢复节点公钥
func (n *nodeKey) RecoverPub(data []byte, signResult *signature.SignResult) (protocol.PubKey, error) {
	pubKey, err := pcrypto.RecoverPubKey(data, signResult)
	if err != nil {
		return nil, err
	}
	p2pPublicKey, err := ToPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	return p2pPublicKey, nil
}

// Sign 签名数据
func (n *nodeKey) Sign(data []byte) (*signature.SignResult, error) {
	return Sign(data, n.prvKey)
}

func (n *nodeKey) Verify(data []byte, signResult *signature.SignResult) (bool, error) {
	return Verify(data, signResult)
}
