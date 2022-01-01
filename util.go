// Package nodekey
//
// @author: xwc1125
package nodekey

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/chain5j/chain5j-pkg/crypto/hashalg"
	"github.com/chain5j/chain5j-pkg/crypto/scrypt"
	"github.com/chain5j/chain5j-pkg/crypto/signature"
	"github.com/chain5j/chain5j-pkg/util/hexutil"
	fileutil "github.com/chain5j/chain5j-pkg/util/ioutil"
	"github.com/chain5j/chain5j-protocol/models"
	pcrypto "github.com/chain5j/chain5j-protocol/pkg/crypto"
	"github.com/chain5j/chain5j-protocol/protocol"
	ci "github.com/libp2p/go-libp2p-core/crypto"
	"golang.org/x/crypto/pkcs12"
)

var (
	ErrFileType = errors.New("unsupported the fileType")
)

var (
	prvAlias = "prvKey"
	pubAlias = "pubKey"
)

type FileType string

const (
	FileType_Hex    = "hex"
	FileType_Base64 = "base64"
	FileType_Pem    = "pem"
	FileType_P12    = "p12"
)

// SavePrivateKey 保存节点私钥到nodekey文件
func SavePrivateKey(prvKey *PrivateKey, fileType FileType, prvKeyFile string, pubKeyFile string, pwd string) error {
	switch fileType {
	case FileType_Hex:
		return saveToHexFile(prvKey, prvKeyFile, pubKeyFile, pwd)
	case FileType_Base64:
		return saveToBase64File(prvKey, prvKeyFile, pubKeyFile, pwd)
	}
	return errors.New("only support the hex and base64")
}
func encryptPrvKey(prvBytes []byte, pwd string) ([]byte, error) {
	encBytes, err := scrypt.EncryptKey(&scrypt.Key{
		// Id:         nil,
		PrivateKey: prvBytes,
	}, pwd, scrypt.LightScryptN, scrypt.LightScryptP)
	if err != nil {
		return nil, err
	}
	return encBytes, nil
}
func saveToHexFile(prvKey *PrivateKey, prvKeyFile string, pubKeyFile string, pwd string) error {
	if len(prvKeyFile) > 0 {
		privBytes, err := prvKey.Marshal()
		if err != nil {
			return fmt.Errorf("marshal prv key err:%v", err)
		}
		if len(pwd) > 0 {
			privBytes, err = encryptPrvKey(privBytes, pwd)
			if err != nil {
				return err
			}
		}

		privData := hexutil.Encode(privBytes)
		err = ioutil.WriteFile(prvKeyFile, []byte(privData), os.ModePerm)
		if err != nil {
			return err
		}
	}
	if len(pubKeyFile) > 0 {
		pubBytes, err := prvKey.publicKey.Marshal()
		if err != nil {
			return fmt.Errorf("marshal pub key err:%v", err)
		}
		pubData := hexutil.Encode(pubBytes)
		err = ioutil.WriteFile(pubKeyFile, []byte(pubData), os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}
func saveToBase64File(prvKey *PrivateKey, prvKeyFile string, pubKeyFile string, pwd string) error {
	if len(prvKeyFile) > 0 {
		privBytes, err := prvKey.Marshal()
		if err != nil {
			return fmt.Errorf("marshal prv key err:%v", err)
		}
		if len(pwd) > 0 {
			privBytes, err = encryptPrvKey(privBytes, pwd)
			if err != nil {
				return err
			}
		}
		privData := base64.StdEncoding.EncodeToString(privBytes)
		err = ioutil.WriteFile(prvKeyFile, []byte(privData), os.ModePerm)
		if err != nil {
			return err
		}
	}
	if len(pubKeyFile) > 0 {
		pubBytes, err := prvKey.publicKey.Marshal()
		if err != nil {
			return fmt.Errorf("marshal pub key err:%v", err)
		}
		pubData := base64.StdEncoding.EncodeToString(pubBytes)
		err = ioutil.WriteFile(pubKeyFile, []byte(pubData), os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}

func loadFromHex(hexBytes []byte, pubBytes []byte, pwd string) (*PrivateKey, error) {
	prvKeyBytes, err := hexutil.Decode(string(hexBytes))
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
}
func loadFromBase64(base64Bytes []byte, pubBytes []byte, pwd string) (*PrivateKey, error) {
	prvKeyBytes, err := base64.StdEncoding.DecodeString(string(base64Bytes))
	if err != nil {
		return nil, err
	}
	if len(pwd) > 0 {
		key, err := scrypt.DecryptKey(prvKeyBytes, pwd)
		if err != nil {
			return nil, err
		}
		prvKeyBytes = key.PrivateKey
	}
	if len(pubBytes) > 0 {
		pubBytes, err = base64.StdEncoding.DecodeString(string(base64Bytes))
		if err != err {
			return nil, err
		}
	}
	privateKey, err := ParsePrivateKeyPem(prvKeyBytes, pubBytes, []byte(pwd))
	if err == nil {
		return privateKey, nil
	}
	prv, err := UnmarshalPrivateKey(prvKeyBytes)
	if err != nil {
		return nil, err
	}
	return NewPrivateKey(prv)
}
func loadFromPem(pemBytes []byte, pubBytes []byte, pwd string) (*PrivateKey, error) {
	return ParsePrivateKeyPem(pemBytes, pubBytes, []byte(pwd))
}
func loadFromP12(pfxBytes []byte, pubBytes []byte, pwd string) (*PrivateKey, error) {
	blocks, err := pkcs12.ToPEM(pfxBytes, pwd)
	var pemData []byte
	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		return nil, err
	}
	return NewPrivateKey(cert.PrivateKey)
}

// LoadPrivateKey 从指定路径下加载nodekey文件
func LoadPrivateKey(fileType FileType, prvKeyFile string, pubKeyFile string, pwd string, args ...string) (*PrivateKey, error) {
	if len(prvKeyFile) == 0 {
		return nil, errInvalidPath
	}

	// 如果不存在，那么自动生成，并保存
	if !fileutil.PathExists(prvKeyFile) {
		err := fileutil.MakeParentDir(prvKeyFile)
		if err != nil {
			return nil, err
		}
		priv, err := GenerateKeyPair(pcrypto.P256)
		if err != nil {
			return nil, err
		}
		err = SavePrivateKey(priv, FileType_Base64, prvKeyFile, pubKeyFile, pwd)
		if err != nil {
			return nil, err
		}
	}

	var (
		prvKeyBytes []byte
		pubKeyBytes []byte
		err         error
	)

	// 获取prv的文件bytes
	prvKeyBytes, err = ioutil.ReadFile(prvKeyFile)
	if err != nil {
		return nil, err
	}
	// 获取pub的文件bytes
	if len(pubKeyFile) > 0 {
		pubKeyBytes, err = ioutil.ReadFile(prvKeyFile)
		if err != nil {
			return nil, err
		}
	}
	switch fileType {
	case FileType_Hex:
		return loadFromHex(prvKeyBytes, pubKeyBytes, pwd)
	case FileType_Base64:
		return loadFromBase64(prvKeyBytes, pubKeyBytes, pwd)
	case FileType_Pem:
		return loadFromPem(prvKeyBytes, pubKeyBytes, pwd)
	case FileType_P12:
		return loadFromP12(prvKeyBytes, pubKeyBytes, pwd)
	default:
		return nil, fmt.Errorf("unsupportted the file type:%s", fileType)
	}
}

func LoadPublicKey(pubFile string) (*PublicKey, error) {
	pubKeyBytes, err := ioutil.ReadFile(pubFile)
	if err != nil {
		return nil, err
	}
	return LoadPublicKeyFromBytes(pubKeyBytes)
}
func LoadPublicKeyFromBytes(pubBytes []byte) (*PublicKey, error) {
	if publicKey, err := ParsePublicKeyPem(pubBytes); err == nil {
		return publicKey, nil
	}
	pubData, isHex, err := decodeHexOrBase64(string(pubBytes))
	if err != nil {
		return nil, err
	}
	var pub crypto.PublicKey
	if isHex {
		pub, err = signature.ToECDSA(pcrypto.SM2P256.KeyName, pubData)
		if err != nil {
			return nil, err
		}
	} else {
		pub, err = UnmarshalPublicKey(pubData)
		if err != nil {
			return nil, err
		}
	}
	return NewPublicKey(pub)
}

// ==================geneKeyPair========================

// GenerateKeyPair 生成p2p对应的公私钥
func GenerateKeyPair(cryptoType pcrypto.CryptoType) (*PrivateKey, error) {
	if cryptoType == pcrypto.Ed25519 {
		// ed25519
		priv, pubk, err := ci.GenerateEd25519Key(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{
			cryptoType: cryptoType,
			prv:        priv,
			publicKey: &PublicKey{
				cryptoType: cryptoType,
				pub:        pubk,
			}}, nil
	}
	keyPair, err := pcrypto.GenerateKeyPair(cryptoType)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		cryptoType: cryptoType,
		prv:        keyPair.Prv,
		publicKey: &PublicKey{
			cryptoType: cryptoType,
			pub:        keyPair.Pub,
		}}, nil
}

// ==================diff key convert========================

// ToPrivateKey 将原生的PrivateKey转换为protocol.PrivateKey
func ToPrivateKey(prvKey crypto.PrivateKey) (*PrivateKey, error) {
	if key, ok := prvKey.(*PrivateKey); ok {
		return key, nil
	}
	if key, ok := prvKey.(*ci.Ed25519PrivateKey); ok {
		bytes, err := key.Raw()
		if err != nil {
			return nil, err
		}
		privKey, err := ci.UnmarshalEd25519PrivateKey(bytes)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{
			cryptoType: pcrypto.Ed25519,
			prv:        privKey,
			publicKey: &PublicKey{
				cryptoType: pcrypto.Ed25519,
				pub:        privKey.GetPublic(),
			}}, nil
	}
	if keyPair, err := pcrypto.ToPrivateKey(prvKey); err == nil {
		return &PrivateKey{
			cryptoType: keyPair.CryptoType,
			prv:        keyPair.Prv,
			publicKey: &PublicKey{
				cryptoType: keyPair.CryptoType,
				pub:        keyPair.Pub,
			}}, nil
	} else {
		return nil, err
	}
}

// ToPublicKey 将原生的PublicKey转换为protocol.PublicKey
func ToPublicKey(pubKey crypto.PublicKey) (*PublicKey, error) {
	if key, ok := pubKey.(*PublicKey); ok {
		return key, nil
	}
	if key, ok := pubKey.(*ci.Ed25519PublicKey); ok {
		return &PublicKey{
			cryptoType: pcrypto.Ed25519,
			pub:        key,
		}, nil
	}
	if keyPair, err := pcrypto.ToPublicKey(pubKey); err == nil {
		return &PublicKey{
			cryptoType: keyPair.CryptoType,
			pub:        keyPair.Pub,
		}, nil
	} else {
		return nil, err
	}
}

// ==================to JsonKey========================

func MarshalPrivateKey(prvKey crypto.PrivateKey) (*pcrypto.JsonKey, error) {
	if key, ok := prvKey.(*PrivateKey); ok {
		return MarshalPrivateKey(key.prv)
	}
	if key, ok := prvKey.(*ci.Ed25519PrivateKey); ok {
		data, err := key.Raw()
		if err != nil {
			return nil, err
		}
		return &pcrypto.JsonKey{
			Type: pcrypto.KeyType_Ed25519,
			Data: data,
		}, nil
	}
	return pcrypto.MarshalPrivateKey(prvKey)
}
func UnmarshalPrivateKey(jsonPrvData []byte) (*PrivateKey, error) {
	var (
		err     error
		jsonPrv pcrypto.JsonKey
	)
	err = jsonPrv.Deserialize(jsonPrvData)
	if err != nil {
		return nil, err
	}
	if jsonPrv.Type == pcrypto.KeyType_Ed25519 {
		sk, err := ci.UnmarshalEd25519PrivateKey(jsonPrv.Data)
		if err != nil {
			return nil, err
		}
		return ToPrivateKey(sk)
	}
	if keyPair, err := pcrypto.ParsePrivateKeyJsonKey(jsonPrv); err == nil {
		return &PrivateKey{
			cryptoType: keyPair.CryptoType,
			prv:        keyPair.Prv,
			publicKey: &PublicKey{
				cryptoType: keyPair.CryptoType,
				pub:        keyPair.Pub,
			},
		}, nil
	} else {
		return nil, err
	}
}
func MarshalPrivateKeyX509(prvKey crypto.PrivateKey) (*pcrypto.JsonKey, error) {
	if key, ok := prvKey.(*PrivateKey); ok {
		return MarshalPrivateKeyX509(key.prv)
	}
	if key, ok := prvKey.(*ci.Ed25519PrivateKey); ok {
		raw, err := key.Raw()
		if err != nil {
			return nil, err
		}
		return &pcrypto.JsonKey{
			Type: pcrypto.KeyType_Ed25519,
			Data: raw,
		}, nil
	}
	return pcrypto.MarshalPrivateKeyX509(prvKey)
}

func MarshalPublicKey(ePub crypto.PublicKey) (*pcrypto.JsonKey, error) {
	if key, ok := ePub.(*PublicKey); ok {
		return MarshalPublicKey(key.pub)
	}
	if key, ok := ePub.(*ci.Ed25519PublicKey); ok {
		raw, err := key.Raw()
		if err != nil {
			return nil, err
		}
		return &pcrypto.JsonKey{
			Type: pcrypto.KeyType_Ed25519,
			Data: raw,
		}, nil
	}
	return pcrypto.MarshalPublicKey(ePub)
}
func UnmarshalPublicKey(jsonKeyBytes []byte) (*PublicKey, error) {
	var (
		err     error
		jsonPrv pcrypto.JsonKey
	)
	err = jsonPrv.Deserialize(jsonKeyBytes)
	if err != nil {
		return nil, err
	}
	if jsonPrv.Type == pcrypto.KeyType_Ed25519 {
		pub, err := ci.UnmarshalEd25519PublicKey(jsonPrv.Data)
		if err != nil {
			return nil, err
		}
		return ToPublicKey(pub)
	}
	if keyPair, err := pcrypto.ParsePublicKeyJsonKey(jsonPrv); err == nil {
		return &PublicKey{
			cryptoType: keyPair.CryptoType,
			pub:        keyPair.Pub,
		}, nil
	} else {
		return nil, err
	}
}
func MarshalPublicKeyX509(ePub crypto.PublicKey) (*pcrypto.JsonKey, error) {
	if key, ok := ePub.(*PublicKey); ok {
		return MarshalPublicKeyX509(key.pub)
	}
	if key, ok := ePub.(*ci.Ed25519PublicKey); ok {
		raw, err := key.Raw()
		if err != nil {
			return nil, err
		}
		return &pcrypto.JsonKey{
			Type: pcrypto.KeyType_Ed25519,
			Data: raw,
		}, nil
	}
	return pcrypto.MarshalPublicKeyX509(ePub)
}

// ==================sign&verify========================

// Sign 签名数据[节点之间的签名]
func Sign(data []byte, prv crypto.PrivateKey) (sig *signature.SignResult, err error) {
	if key, ok := prv.(*PrivateKey); ok {
		return Sign(data, key.prv)
	}
	if key, ok := prv.(*ci.Ed25519PrivateKey); ok {
		hashed := hashalg.Sha256(data)
		sig1, err := key.Sign(hashed[:])
		if err != nil {
			return nil, err
		}
		jsonKey, err := MarshalPublicKey(key.GetPublic())
		if err != nil {
			return nil, err
		}
		return &signature.SignResult{
			Name:      pcrypto.Ed25519.KeyName,
			PubKey:    jsonKey.SerializeUnsafe(),
			Signature: sig1,
		}, nil
	}
	return pcrypto.Sign(data, prv)
}

// Verify 验证签名内容
// sigBytes 是signResult的bytes值
func Verify(data []byte, signResult *signature.SignResult) (bool, error) {
	cryptoType, err := pcrypto.ParseKeyName(signResult.Name)
	if err != nil {
		return false, err
	}
	if cryptoType.KeyType == pcrypto.KeyType_Ed25519 {
		publicKey, err := UnmarshalPublicKey(signResult.PubKey)
		if err != nil {
			return false, err
		}
		ed25519PublicKey := publicKey.pub.(*ci.Ed25519PublicKey)
		hashed := hashalg.Sha256(data)
		return ed25519PublicKey.Verify(hashed[:], signResult.Signature)
	}
	return pcrypto.Verify(data, signResult)
}

// RecoverId 从签名中恢复出ID
func RecoverId(data []byte, signResult *signature.SignResult) (models.NodeID, error) {
	pub, err := pcrypto.RecoverPubKey(data, signResult)
	if err != nil {
		return "", err
	}
	return IdFromPub(pub)
}

// ==================pem or der========================

// ParsePrivateKeyPem parse key pem to privateKey
func ParsePrivateKeyPem(keyPemBytes, certPemBytes []byte, pwd []byte) (privateKey *PrivateKey, err error) {
	keyPair, err := pcrypto.ParsePrivateKeyPem(keyPemBytes, certPemBytes, pwd)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		cryptoType: keyPair.CryptoType,
		prv:        keyPair.Prv,
		publicKey: &PublicKey{
			cryptoType: keyPair.CryptoType,
			pub:        keyPair.Pub,
		},
	}, nil
}

// ParsePublicKeyPem parse key pem to publicKey
func ParsePublicKeyPem(keyPemBytes []byte) (*PublicKey, error) {
	keyPair, err := pcrypto.ParsePublicKeyPem(keyPemBytes)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		cryptoType: keyPair.CryptoType,
		pub:        keyPair.Pub,
	}, nil
}

func SaveToPemFile(prvKey *PrivateKey, prvKeyFile string, pubKeyFile string, pwd string) error {
	if len(prvKeyFile) != 0 {
		prvKeyBytes, err := prvKey.Raw()
		if err != nil {
			return err
		}
		if len(prvKeyBytes) == 0 {
			return fmt.Errorf("prvKey bytes is empty")
		}

		// 私钥处理
		{
			block := &pem.Block{
				Type:  pcrypto.CryptoLabel(prvKey.cryptoType) + " PRIVATE KEY",
				Bytes: prvKeyBytes,
			}

			buf := new(bytes.Buffer)
			if err = pem.Encode(buf, block); err != nil {
				return err
			}
			fileutil.MakeParentDir(prvKeyFile)
			err := os.WriteFile(prvKeyFile, buf.Bytes(), os.ModePerm)
			if err != nil {
				return fmt.Errorf("write prvKey err:%v", err)
			}
		}
	}
	// 公钥处理
	if len(pubKeyFile) != 0 {
		pubKeyBytes, err := prvKey.publicKey.Raw()
		if err != nil {
			return err
		}
		block := &pem.Block{
			Type:  pcrypto.CryptoLabel(prvKey.cryptoType) + " PUBLIC KEY",
			Bytes: pubKeyBytes,
		}

		buf := new(bytes.Buffer)
		if err = pem.Encode(buf, block); err != nil {
			return err
		}
		fileutil.MakeParentDir(pubKeyFile)
		err = os.WriteFile(pubKeyFile, buf.Bytes(), os.ModePerm)
		if err != nil {
			return fmt.Errorf("write pubKey err:%v", err)
		}
	}
	return nil
}

// ==================tool========================

// IdFromPub 将ecdsa publicKey转换为NodeId
func IdFromPub(pub crypto.PublicKey) (models.NodeID, error) {
	p2pPublicKey, err := ToPublicKey(pub)
	if err != nil {
		return "", err
	}
	id, err := IDFromPublicKey(p2pPublicKey)
	if err != nil {
		return "", fmt.Errorf("pub key to peer id err:%v", err)
	}

	return id, nil
}

// IDFromPrivateKey 通过私钥获取PeerID
func IDFromPrivateKey(sk protocol.PrivKey) (models.NodeID, error) {
	return pcrypto.IDFromPrivateKey(sk)
}

// IDFromPublicKey 根据公钥生成PeerID
func IDFromPublicKey(pk protocol.PubKey) (models.NodeID, error) {
	return pcrypto.IDFromPublicKey(pk)
}

// decodeHexOrBase64 判断是16进制还是64进制
func decodeHexOrBase64(content string) (bytes []byte, isHex bool, err error) {
	dat := []byte(content)
	isHex = true
	for _, v := range dat {
		if v >= 48 && v <= 57 || v >= 65 && v <= 70 || v >= 97 && v <= 102 {
			isHex = true
		} else {
			isHex = false
			break
		}
	}
	if isHex {
		bytes, err = hex.DecodeString(content)
		if len(bytes) == 0 || err != nil {
			bytes, err = base64.StdEncoding.DecodeString(content)
		}
	} else {
		bytes, err = base64.StdEncoding.DecodeString(content)
	}
	return
}
