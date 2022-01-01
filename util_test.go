// Package nodekey
//
// @author: xwc1125
package nodekey

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/chain5j/chain5j-pkg/crypto/scrypt"
	"github.com/chain5j/chain5j-pkg/crypto/signature"
	"github.com/chain5j/chain5j-pkg/util/hexutil"
	"github.com/chain5j/chain5j-protocol/models"
	pcrypto "github.com/chain5j/chain5j-protocol/pkg/crypto"
	"github.com/chain5j/chain5j-protocol/protocol"
	"github.com/chain5j/logger"
	"github.com/chain5j/logger/zap"
	ci "github.com/libp2p/go-libp2p-core/crypto"
)

func init() {
	zap.InitWithConfig(&logger.LogConfig{
		Console: logger.ConsoleLogConfig{
			Level:    4,
			Modules:  "*",
			ShowPath: false,
			Format:   "",
			UseColor: true,
			Console:  true,
		},
		File: logger.FileLogConfig{},
	})
}

func TestGenerateKeyPair(t *testing.T) {
	// rsa
	privKey, err := GenerateKeyPair(pcrypto.RSA)
	if err != nil {
		t.Fatal(err)
	}
	testPrivKey(privKey)
	// p256
	privKey, err = GenerateKeyPair(pcrypto.P256)
	if err != nil {
		panic(err)
	}
	testPrivKey(privKey)
	// p384
	privKey, err = GenerateKeyPair(pcrypto.P384)
	if err != nil {
		panic(err)
	}
	testPrivKey(privKey)
	// P521
	privKey, err = GenerateKeyPair(pcrypto.P521)
	if err != nil {
		panic(err)
	}
	testPrivKey(privKey)
	// s256
	privKey, err = GenerateKeyPair(pcrypto.S256)
	if err != nil {
		panic(err)
	}
	testPrivKey(privKey)
	// sm2
	privKey, err = GenerateKeyPair(pcrypto.SM2P256)
	if err != nil {
		panic(err)
	}
	testPrivKey(privKey)
	// ed25519
	privKey, err = GenerateKeyPair(pcrypto.Ed25519)
	if err != nil {
		panic(err)
	}
	testPrivKey(privKey)
}
func testPrivKey(privKey *PrivateKey) {
	p2pPrivateKey, err := ToPrivateKey(privKey.prv)
	if err != nil {
		panic(err)
	}
	nodeID, _ := p2pPrivateKey.ID()
	fmt.Println("NodeID", nodeID)
	_ = p2pPrivateKey
	p2pPublicKey, err := ToPublicKey(privKey.publicKey.pub)
	if err != nil {
		panic(err)
	}
	_ = p2pPublicKey

	signResult, err := Sign([]byte("123"), p2pPrivateKey)
	if err != nil {
		panic(err)
	}
	marshal, _ := json.Marshal(signResult)
	fmt.Println(string(marshal))
	verify, err := p2pPublicKey.Verify([]byte("123"), signResult)
	if err != nil {
		panic(err)
	}
	fmt.Println(verify)
}

func TestMarshalPrivateKey(t *testing.T) {
	// rsa
	{
		privKey, err := GenerateKeyPair(pcrypto.RSA)
		if err != nil {
			panic(err)
		}
		testMarshal(privKey)
	}

	// p256
	{
		privKey, err := GenerateKeyPair(pcrypto.P256)
		if err != nil {
			panic(err)
		}
		testMarshal(privKey)
	}
	// P384
	{
		privKey, err := GenerateKeyPair(pcrypto.P384)
		if err != nil {
			panic(err)
		}
		testMarshal(privKey)
	}
	// P521
	{
		privKey, err := GenerateKeyPair(pcrypto.P521)
		if err != nil {
			panic(err)
		}
		testMarshal(privKey)
	}
	// s256
	{
		privKey, err := GenerateKeyPair(pcrypto.S256)
		if err != nil {
			panic(err)
		}
		testMarshal(privKey)
	}

	// sm2
	{
		privKey, err := GenerateKeyPair(pcrypto.SM2P256)
		if err != nil {
			panic(err)
		}
		testMarshal(privKey)
	}

	// ed25519
	{
		privKey, err := GenerateKeyPair(pcrypto.Ed25519)
		if err != nil {
			panic(err)
		}
		testMarshal(privKey)
	}

}
func testMarshal(privKey *PrivateKey) {
	privateKeyJsonKey, err := MarshalPrivateKey(privKey.prv)
	if err != nil {
		panic(err)
	}
	fmt.Println("privateKeyJsonKey", hexutil.Encode(privateKeyJsonKey.SerializeUnsafe()))
	privateKey, err := UnmarshalPrivateKey(privateKeyJsonKey.SerializeUnsafe())
	if err != nil {
		panic(err)
	}
	privateKeyJsonKey, err = MarshalPrivateKey(privateKey.prv)
	if err != nil {
		panic(err)
	}
	fmt.Println("privateKeyJsonKey2", hexutil.Encode(privateKeyJsonKey.SerializeUnsafe()))

	publicKeyJsonKey, err := MarshalPublicKey(privKey.publicKey.pub)
	if err != nil {
		panic(err)
	}
	fmt.Println("publicKeyJsonKey", hexutil.Encode(publicKeyJsonKey.SerializeUnsafe()))
	publicKey, err := UnmarshalPublicKey(publicKeyJsonKey.SerializeUnsafe())
	if err != nil {
		panic(err)
	}
	publicKeyJsonKey, err = MarshalPublicKey(publicKey.pub)
	if err != nil {
		panic(err)
	}
	fmt.Println("publicKeyJsonKey2", hexutil.Encode(publicKeyJsonKey.SerializeUnsafe()))
}

func TestSign(t *testing.T) {
	// rsa
	{
		privKey, err := GenerateKeyPair(pcrypto.RSA)
		if err != nil {
			panic(err)
		}
		testSign(privKey)
	}

	// p256
	{
		privKey, err := GenerateKeyPair(pcrypto.P256)
		if err != nil {
			panic(err)
		}
		testSign(privKey)
	}
	// P384
	{
		privKey, err := GenerateKeyPair(pcrypto.P384)
		if err != nil {
			panic(err)
		}
		testSign(privKey)
	}
	// P521
	{
		privKey, err := GenerateKeyPair(pcrypto.P521)
		if err != nil {
			panic(err)
		}
		testSign(privKey)
	}
	// s256
	{
		privKey, err := GenerateKeyPair(pcrypto.S256)
		if err != nil {
			panic(err)
		}
		testSign(privKey)
	}

	// sm2
	{
		privKey, err := GenerateKeyPair(pcrypto.SM2P256)
		if err != nil {
			panic(err)
		}
		testSign(privKey)
	}

	// ed25519
	{
		privKey, err := GenerateKeyPair(pcrypto.Ed25519)
		if err != nil {
			panic(err)
		}
		testSign(privKey)
	}

}
func testSign(privKey *PrivateKey) {
	msg := []byte("Hello world!123456789")
	signResult, err := Sign(msg, privKey.prv)
	if err != nil {
		panic(err)
	}
	marshal, _ := json.Marshal(signResult)
	fmt.Println("signResult", string(marshal))

	verify, err := Verify(msg, signResult)
	if err != nil {
		panic(err)
	}
	fmt.Println("verify", verify)
	if !verify {
		panic("verify err")
	}
	id, err := RecoverId(msg, signResult)
	if err != nil {
		panic(err)
	}
	fmt.Println("ID", id)
}

func TestPrivKeyWithDer(t *testing.T) {
	// rsa
	{
		privKey, err := GenerateKeyPair(pcrypto.RSA)
		if err != nil {
			panic(err)
		}
		testPrivKeyWithDer(privKey)
	}
	// p256
	{
		privKey, err := GenerateKeyPair(pcrypto.P256)
		if err != nil {
			panic(err)
		}
		testPrivKeyWithDer(privKey)
	}
	// p384
	{
		privKey, err := GenerateKeyPair(pcrypto.P384)
		if err != nil {
			panic(err)
		}
		testPrivKeyWithDer(privKey)
	}
	// p521
	{
		privKey, err := GenerateKeyPair(pcrypto.P521)
		if err != nil {
			panic(err)
		}
		testPrivKeyWithDer(privKey)
	}
	// s256
	{
		privKey, err := GenerateKeyPair(pcrypto.S256)
		if err != nil {
			panic(err)
		}
		testPrivKeyWithDer(privKey)
	}
	// sm2
	{
		privKey, err := GenerateKeyPair(pcrypto.SM2P256)
		if err != nil {
			panic(err)
		}
		testPrivKeyWithDer(privKey)
	}
	// ed25519
	{
		privKey, err := GenerateKeyPair(pcrypto.Ed25519)
		if err != nil {
			panic(err)
		}
		testPrivKeyWithDer(privKey)
	}
}
func testPrivKeyWithDer(privKey *PrivateKey) {
	p2pPrivateKey, err := ToPrivateKey(privKey.prv)
	if err != nil {
		panic(err)
	}
	// 生成x509的der[rsa]
	bytes, err := p2pPrivateKey.Raw()
	if err != nil {
		panic(err)
	}
	fmt.Println("privateKeyPem:", hexutil.Encode(bytes))
	_, err = pcrypto.PrivKeyWithDer(bytes)
	if err != nil {
		panic(err)
	}

	pubBytes, err := p2pPrivateKey.GetPublic().Raw()
	if err != nil {
		panic(err)
	}
	fmt.Println("publicKeyPem:", hexutil.Encode(pubBytes))
	prvFile := "./logs/" + privKey.cryptoType.KeyName + "-key.pem"
	pubFile := "./logs/" + privKey.cryptoType.KeyName + "-pub.pem"
	err = SaveToPemFile(privKey, prvFile, pubFile, "")
	if err != nil {
		panic(err)
	}
	fmt.Println("================================")
	nodeKey, err := LoadPrivateKey(FileType_Pem, prvFile, pubFile, "")
	if err != nil {
		panic(err)
	}
	_ = nodeKey
	pubKey, err := LoadPublicKey(pubFile)
	if err != nil {
		panic(err)
	}
	_ = pubKey
}

func TestCompileWithPeerID(t *testing.T) {
	keyPem := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIF59m4rsjA2YNFXraoAmdzc+TRtJdsckdcXO1jIXGBUqoAoGCCqGSM49
AwEHoUQDQgAEfn7lPb3OOqmjtSfGEJi28uLbhUh0ZXgo/qyCu/YO7OBaxAHqb1hs
u7e2TwH5MQ0QekYfF+phmJaEFRgE3wr1eA==
-----END EC PRIVATE KEY-----`
	prvKey, err := loadFromPem([]byte(keyPem), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// QmcSbxCegVeorqoif6fYKLiMgbv7tJkJFQNDdmFK2G3F9j
	id, err := prvKey.ID()
	if err != nil {
		t.Fatal(err)
	}
	if id != "QmcSbxCegVeorqoif6fYKLiMgbv7tJkJFQNDdmFK2G3F9j" && id != "JDq8kTCbdtuNqinHpEzR7caPUTXicVkT7tDCyGHRXWGU" {
		t.Fatal("peer is diff")
	}

	cert, err := keyToCertificate(prvKey)
	if err != nil {
		panic(err)
	}
	chain := make([]*x509.Certificate, 0)
	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	chain = append(chain, certificate)
	// PubKeyFromCertChain(chain)
	PubKeyFromCertChain2(chain)
}

func TestSaveLoad(t *testing.T) {
	keyPem := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIF59m4rsjA2YNFXraoAmdzc+TRtJdsckdcXO1jIXGBUqoAoGCCqGSM49
AwEHoUQDQgAEfn7lPb3OOqmjtSfGEJi28uLbhUh0ZXgo/qyCu/YO7OBaxAHqb1hs
u7e2TwH5MQ0QekYfF+phmJaEFRgE3wr1eA==
-----END EC PRIVATE KEY-----`
	nodeKey, id := getNodeKey(t, keyPem)
	if id != "QmcSbxCegVeorqoif6fYKLiMgbv7tJkJFQNDdmFK2G3F9j" && id != "JDq8kTCbdtuNqinHpEzR7caPUTXicVkT7tDCyGHRXWGU" {
		t.Fatal("peer is diff")
	}
	var pwd = "123456"
	var subPrefix = "_enc"
	var prvKeyFile = "./logs/" + id.String() + "prvKey" + subPrefix + ".hex"
	var pubKeyFile = "./logs/" + id.String() + "pubKey" + subPrefix + ".hex"
	// hex
	{
		err := SavePrivateKey(nodeKey, FileType_Hex, prvKeyFile, pubKeyFile, pwd)
		if err != nil {
			t.Error(err)
		}
		prvKey, err := LoadPrivateKey(FileType_Hex, prvKeyFile, pubKeyFile, pwd)
		if err != nil {
			t.Error("LoadPrivateKey", err)
		}
		peerID, _ := prvKey.ID()
		t.Log("Id", peerID)
	}
	// base64
	{
		prvKeyFile = "./logs/" + id.String() + "prvKey" + subPrefix + ".base64"
		pubKeyFile = "./logs/" + id.String() + "pubKey" + subPrefix + ".base64"
		err := SavePrivateKey(nodeKey, FileType_Base64, prvKeyFile, pubKeyFile, pwd)
		if err != nil {
			t.Error(err)
		}
		prvKey, err := LoadPrivateKey(FileType_Base64, prvKeyFile, pubKeyFile, pwd)
		if err != nil {
			t.Fatal("LoadPrivateKey", err)
		}
		peerID, _ := prvKey.ID()
		t.Log("Id", peerID)
	}
}
func TestLoadPem(t *testing.T) {
	// Pem
	{
		prvKeyFile := "../../conf/certs/ssl/client/client-key.pem"
		pubKeyFile := "../../conf/certs/ssl/client/client.pem"
		prvKey, err := LoadPrivateKey(FileType_Pem, prvKeyFile, pubKeyFile, "")
		if err != nil {
			t.Fatal("LoadPrivateKey", err)
		}
		peerID, _ := prvKey.ID()
		t.Log("Id", peerID)
	}
}
func TestLoadP12(t *testing.T) {
	// P12
	{
		// ANoGdn3i8d7MQCM69f7EKGzuMMzStnkdxDBBk64bws2m
		prvKeyFile := "../../conf/certs/ssl/client/client.p12"
		pubKeyFile := "../../conf/certs/ssl/client/client.pem"
		prvKey, err := LoadPrivateKey(FileType_P12, prvKeyFile, pubKeyFile, "123456")
		if err != nil {
			t.Fatal("LoadPrivateKey", err)
		}
		peerID, _ := prvKey.ID()
		t.Log("Id", peerID)
	}
}

func getNodeKey(t *testing.T, keyPem string) (*PrivateKey, models.NodeID) {
	prvKey, err := loadPrivateKeyFromBytes([]byte(keyPem), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	id, err := prvKey.ID()
	if err != nil {
		t.Fatal(err)
	}
	return prvKey, id
}

func loadPrivateKeyFromBytes(prvKeyBytes []byte, pubKeyBytes []byte, pwd string) (*PrivateKey, error) {
	// 判断prv是否为hex
	prvKeyStr := string(prvKeyBytes)
	isHex := hexutil.IsHex(prvKeyStr)
	if isHex {
		prvKeyBytes, err := hexutil.Decode(prvKeyStr)
		if len(pwd) > 0 {
			key, err := scrypt.DecryptKey(prvKeyBytes, pwd)
			if err != nil {
				return nil, err
			}
			prvKeyBytes = key.PrivateKey
		}
		prv, err := UnmarshalPrivateKey(prvKeyBytes)
		if err != nil {
			return nil, err
		}
		return NewPrivateKey(prv)
	} else {
		prvKeyBytes1, err := base64.StdEncoding.DecodeString(prvKeyStr)
		if err == nil {
			pubKeyBytes = prvKeyBytes1
		}
		if len(pwd) > 0 {
			key, err := scrypt.DecryptKey(pubKeyBytes, pwd)
			if err != nil {
				return nil, err
			}
			prvKeyBytes = key.PrivateKey
		}
		privateKey, err := ParsePrivateKeyPem(prvKeyBytes, pubKeyBytes, []byte(pwd))
		if err == nil {
			return privateKey, nil
		}
		prv, err := UnmarshalPrivateKey(prvKeyBytes)
		if err != nil {
			return nil, err
		}
		return NewPrivateKey(prv)
	}
}

const certValidityPeriod = 100 * 365 * 24 * time.Hour // ~100 years
const certificatePrefix = "libp2p-tls-handshake:"

var extensionID = getPrefixedExtensionID([]int{1, 1})

var extensionPrefix = []int{1, 3, 6, 1, 4, 1, 53594}

// getPrefixedExtensionID returns an Object Identifier
// that can be used in x509 Certificates.
func getPrefixedExtensionID(suffix []int) []int {
	return append(extensionPrefix, suffix...)
}

type signedKey struct {
	PubKey    []byte
	Signature []byte
}

func keyToCertificate(sk protocol.PrivKey) (*tls.Certificate, error) {
	keyType := sk.Type()
	cryptoType, err := pcrypto.ParseKeyType((int32)(keyType))
	nodeKey, err := GenerateKeyPair(cryptoType)
	certKey := nodeKey.prv
	pubKey := nodeKey.publicKey
	if err != nil {
		return nil, err
	}
	certKeyPub, err := pubKey.Raw()
	if err != nil {
		return nil, err
	}
	signResult, err := sk.Sign(append([]byte(certificatePrefix), certKeyPub...))
	if err != nil {
		return nil, err
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	signatureBytes, err := signResult.Serialize()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		NotBefore:    time.Time{},
		NotAfter:     time.Now().Add(certValidityPeriod),
		// after calling CreateCertificate, these will end up in Certificate.Extensions
		ExtraExtensions: []pkix.Extension{
			{Id: extensionID, Value: signatureBytes},
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubKey.pub, certKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  certKey,
	}, nil
}

func extensionIDEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func PubKeyFromCertChain(chain []*x509.Certificate) (ci.PubKey, error) {
	if len(chain) != 1 {
		return nil, errors.New("expected one certificates in the chain")
	}
	cert := chain[0]
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		return nil, fmt.Errorf("certificate verification failed: %s", err)
	}

	var found bool
	var keyExt pkix.Extension
	for _, ext := range cert.Extensions {
		if extensionIDEqual(ext.Id, extensionID) {
			keyExt = ext
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("expected certificate to contain the key extension")
	}
	// asn1.Unmarshal
	var sk signedKey
	if _, err := asn1.Unmarshal(keyExt.Value, &sk); err != nil {
		return nil, fmt.Errorf("unmarshalling signed certificate failed: %s", err)
	}
	pubKey, err := ci.UnmarshalPublicKey(sk.PubKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling public key failed: %s", err)
	}
	certKeyPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	valid, err := pubKey.Verify(append([]byte(certificatePrefix), certKeyPub...), sk.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %s", err)
	}
	if !valid {
		return nil, errors.New("signature invalid")
	}
	return pubKey, nil
}

func PubKeyFromCertChain2(chain []*x509.Certificate) (protocol.PubKey, error) {
	if len(chain) != 1 {
		return nil, errors.New("expected one certificates in the chain")
	}
	cert := chain[0]
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		// If we return an x509 error here, it will be sent on the wire.
		// Wrap the error to avoid that.
		return nil, fmt.Errorf("certificate verification failed: %s", err)
	}

	var found bool
	var keyExt pkix.Extension
	// find the key extension, skipping all unknown extensions
	for _, ext := range cert.Extensions {
		if extensionIDEqual(ext.Id, extensionID) {
			keyExt = ext
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("expected certificate to contain the key extension")
	}
	// asn1.Unmarshal
	var sk signature.SignResult
	err := sk.Deserialize(keyExt.Value)
	// if _, err := asn1.Unmarshal(keyExt.Value, &sk); err != nil {
	//	return nil, fmt.Errorf("unmarshalling signed certificate failed: %s", err)
	// }
	pubKey, err := UnmarshalPublicKey(sk.PubKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling public key failed: %s", err)
	}
	certKeyPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	valid, err := pubKey.Verify(append([]byte(certificatePrefix), certKeyPub...), &sk)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %s", err)
	}
	if !valid {
		return nil, errors.New("signature invalid")
	}
	return pubKey, nil
}

func TestRecoverId2(t *testing.T) {
	keyPem := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIF59m4rsjA2YNFXraoAmdzc+TRtJdsckdcXO1jIXGBUqoAoGCCqGSM49
AwEHoUQDQgAEfn7lPb3OOqmjtSfGEJi28uLbhUh0ZXgo/qyCu/YO7OBaxAHqb1hs
u7e2TwH5MQ0QekYfF+phmJaEFRgE3wr1eA==
-----END EC PRIVATE KEY-----`
	nodeKey, id := getNodeKey(t, keyPem)
	// chain5j：JDq8kTCbdtuNqinHpEzR7caPUTXicVkT7tDCyGHRXWGU
	// P2P：QmcSbxCegVeorqoif6fYKLiMgbv7tJkJFQNDdmFK2G3F9j
	if id != "QmcSbxCegVeorqoif6fYKLiMgbv7tJkJFQNDdmFK2G3F9j" && id != "JDq8kTCbdtuNqinHpEzR7caPUTXicVkT7tDCyGHRXWGU" {
		t.Fatal("peer is diff")
	}

	testSign(nodeKey)
}
