// Package nodekey
//
// @author: xwc1125
package nodekey

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/chain5j/chain5j-pkg/crypto/hashalg/sha3"
	"github.com/chain5j/chain5j-protocol/mock"
	"github.com/chain5j/chain5j-protocol/models"
	pcrypto "github.com/chain5j/chain5j-protocol/pkg/crypto"
	"github.com/chain5j/logger"
	"github.com/golang/mock/gomock"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/stretchr/testify/assert"
)

func TestFactory_NewFactory(t *testing.T) {
	mockCtl := gomock.NewController(nil)
	mockConfig := mock.NewMockConfig(mockCtl)
	mockConfig.EXPECT().NodeKeyConfig().Return(models.NodeKeyLocalConfig{
		PrvKeyFile:   "./logs/nodekey",
		PubKeyFile:   "",
		Password:     "",
		Metrics:      false,
		MetricsLevel: 0,
	}).AnyTimes()
	nodeKey, err := NewNodeKey(
		context.Background(),
		WithConfig(mockConfig),
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = nodeKey
}

func GenRsaKey(bits int) error {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derPkix,
	}
	file, err = os.Create("public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

func TestGene(t *testing.T) {
	GenRsaKey(2048)
}

func TestLoadNodeFromData(t *testing.T) {
	// decodeString, err2 := base64.StdEncoding.DecodeString("BggqgRzPVQGCLQ==")
	// decodeString, err2 := base64.StdEncoding.DecodeString("BgUrgQQACg==")
	// if err2 != nil {
	//	panic(err2)
	// }
	// logger.Println(string(decodeString))
	// 16进制
	keyData := "587CA4A15BC4D239CFBA433DDA03366506E99ECD2C529216EB3168B3E7806257"
	nodeKey, err := loadFromHex([]byte(keyData), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	logger.Println("hex", nodeKey)

	// // [不支持]64进制：proto.Unmarshal，ci.UnmarshalPrivateKey
	// keyData = "CAMSeTB3AgEBBCC8Ni2izOENJNfw6zLxjQAif2BsohWdw8zbqGjElbG3aqAKBggqhkjOPQMBB6FEA0IABDPItMvltCQsgeNLu70AIWiMJeUxO0ucsII6d7nZP17sMYC+dMI4/yvgiMXteaT4/DDIlQCFRJHgigMQaLg6XXI="
	// nodeKey, err = LoadNodeFromData(keyData)
	// if err != nil {
	//	t.Fatal(err)
	// }
	// logger.Println(nodeKey)

	// pem

	// sm2 √
	keyData = `-----BEGIN EC PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgxWKtZVUie2kgeguh
RvfHhesupVHyG3bUjly0O8jP4iCgCgYIKoEcz1UBgi2hRANCAATsNg3elXzJi+Ax
lfTQB09qmloV7YNaWYQ5aMAFDBBFrUh4l7nLP42bwpexT/AyXlONSp7maM/Vkf/B
bFpinKOz
-----END EC PRIVATE KEY-----
`
	nodeKey, err = loadFromPem([]byte(keyData), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	logger.Println("sm2", nodeKey)
	// p256 √
	keyData = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIF59m4rsjA2YNFXraoAmdzc+TRtJdsckdcXO1jIXGBUqoAoGCCqGSM49
AwEHoUQDQgAEfn7lPb3OOqmjtSfGEJi28uLbhUh0ZXgo/qyCu/YO7OBaxAHqb1hs
u7e2TwH5MQ0QekYfF+phmJaEFRgE3wr1eA==
-----END EC PRIVATE KEY-----
	`
	nodeKey, err = loadFromPem([]byte(keyData), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	logger.Println("p256", nodeKey)
	// secp256k1 err==>openssl
	keyData = `-----BEGIN EC PARAMETERS-----
BgUrgQQACg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIHd6pwLDNP44k3Ns2RP7Zf3vjevcIaSQCubgr89Y3W1soAcGBSuBBAAK
oUQDQgAEKRDwvp+sZpzBGJujEQ99DWhrRzN6Z/9+Hj/QO9v/bQx6MibXGsspnXc7
qszXemPPne41AtoLXRJJIw/gcRqO/Q==
-----END EC PRIVATE KEY-----
	`
	nodeKey, err = loadFromPem([]byte(keyData), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	logger.Println("secp256k1 err==>openssl", nodeKey)
	// sm2 err==>openssl
	keyData = `-----BEGIN EC PARAMETERS-----
BggqgRzPVQGCLQ==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOHSA5sO6QbqmGM1mrtplIDUth92o3yyPh7R6C7jhsS2oAoGCCqBHM9V
AYItoUQDQgAE6fyV2irf4j5DxR3BRidJ3v30TFavyz6skDPjA8TQgoMJF3iCFbqV
B4GxVcjkqucDPZ1khgq9l72krT7Lg0Yqag==
-----END EC PRIVATE KEY-----
	`
	nodeKey, err = loadFromPem([]byte(keyData), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	logger.Println("sm2 err==>openssl", nodeKey)
}

func TestGenerateNodekey(t *testing.T) {
	key, err := GenerateKeyPair(pcrypto.P256)
	if err != nil {
		t.Fatal(err)
	}
	nodeId, err := key.ID()
	fmt.Println(nodeId)
	privBytes, err := key.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	privData := base64.StdEncoding.EncodeToString(privBytes)

	t.Logf("Generate Private Key:%s", privData)
}

func TestRecoverId(t *testing.T) {
	keyString := "CAMSeTB3AgEBBCCi7hIrawml72q7DiOrqSGvnN+7/XQY/8dCQ9ir2zwXxqAKBggqhkjOPQMBB6FEA0IABEVeUwNa+ZgQsp9pDBrxF7pvHoV1DV+CErcv7TqtUzHhiDtV9q0FyiMgC911xLbQzQzAlJW+T8TvC15m+fIkxe8="
	expectId := "QmdnqdoLkbeoLgSDCmUeVffCm7diRyABCchkPRMj69YB6h"

	key, err := loadFromBase64([]byte(keyString), nil, "")
	if err != nil {
		t.Fatal(err)
	}

	id, err := key.ID()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expectId, id)

	hash := sha3.Keccak256([]byte("123"))
	sig, err := Sign(hash, key)
	if err != nil {
		t.Fatal(err)
	}

	rid, err := RecoverId(hash, sig)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expectId, rid)
}

func TestNodeKeyFile(t *testing.T) {
	priv, _, _ := crypto.GenerateECDSAKeyPair(rand.Reader)
	privateKey, err := NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := SavePrivateKey(privateKey, FileType_Base64, "./nodekey", "", ""); err != nil {
		t.Fatal(err)
	}

	// load, err := LoadPrivateKey("./nodekey")
	// if err != nil {
	//	t.Fatal(err)
	// }
	//
	// privHex, _ := priv.Bytes()
	// loadHex, _ := load.P2PPrvKey().Bytes()
	//
	// if bytes.Compare(privHex, loadHex) != 0 {
	//	t.Fatal("load nodekey error")
	// }

	os.Remove(nodekeyFile)
}

func TestPublicKey_Type(t *testing.T) {
	privKey, pubKey0, _ := crypto.GenerateECDSAKeyPair(rand.Reader)
	keyBytes1, err := crypto.MarshalPublicKey(privKey.GetPublic())
	if err != nil {
		t.Fatal(err)
	}
	_ = pubKey0
	// 此处会出问题
	pubKey1, err := crypto.UnmarshalPublicKey(keyBytes1)
	if err != nil {
		t.Fatal(err)
	}
	logger.Println(pubKey1)

	// sk, err := GenerateKeyPair(P256)
	// if err != nil {
	//	t.Fatal(err)
	// }
	// keyBytes, err := crypto.MarshalPublicKey(sk.GetPublic())
	// if err != nil {
	//	t.Fatal(err)
	// }
	// 此处会出问题
	// pubKey, err := crypto.UnmarshalPublicKey(keyBytes)
	// if err != nil {
	//	t.Fatal(err)
	// }
	// logger.Println(pubKey)
}
