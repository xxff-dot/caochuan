package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CertManager 持有隧道 TLS 配置与证书指纹。
type CertManager struct {
	tlsConf     *tls.Config
	fingerprint string // SHA-256(证书 DER) 的 hex，client 用于锁定
}

// Fingerprint 返回证书指纹；未启用 TLS 时为空。
func (m *CertManager) Fingerprint() string { return m.fingerprint }

func (m *CertManager) TLSConfig() *tls.Config { return m.tlsConf }

// LoadOrGenerate 读取配置的自有证书，否则在配置同目录自动生成自签证书并落盘。
func LoadOrGenerate(cfgPath string, certFile, keyFile string) (*CertManager, error) {
	if certFile == "" || keyFile == "" {
		dir := filepath.Dir(cfgPath)
		certFile = filepath.Join(dir, "server.crt")
		keyFile = filepath.Join(dir, "server.key")
	}
	if _, err := os.Stat(certFile); err == nil {
		if _, err2 := os.Stat(keyFile); err2 == nil {
			pair, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("加载 TLS 证书失败: %w", err)
			}
			return newManager(pair)
		}
	}

	// 自动生成自签证书（ECDSA P-256，10 年）
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "caochuan"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyPEM, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	slog.Info("已生成自签 TLS 证书", "cert", certFile, "key", keyFile)

	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM}))
	if err != nil {
		return nil, err
	}
	return newManager(pair)
}

func newManager(pair tls.Certificate) (*CertManager, error) {
	sum := sha256.Sum256(pair.Certificate[0]) // 与 client 端指纹算法一致：SHA-256(证书 DER)
	return &CertManager{
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{pair},
			MinVersion:   tls.VersionTLS12,
		},
		fingerprint: hex.EncodeToString(sum[:]),
	}, nil
}
