package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
)

func GenerateKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func GenerateCertificate() *x509.Certificate {
	var b [13]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return &x509.Certificate{Version: 3, SerialNumber: big.NewInt(1).SetBytes(b[:])}
}

func WriteCert(cert *x509.Certificate, filename string) {
	if err := os.WriteFile(filename, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0644); err != nil {
		panic(err)
	}
}

func WriteKey(key *ecdsa.PrivateKey, filename string) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(filename, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0644); err != nil {
		panic(err)
	}
}

func LoadCertFromFile(certFile, keyFile string) (certificate *x509.Certificate, privateKey any) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic(err)
	}

	if certificate, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		panic(err)
	}
	privateKey = cert.PrivateKey
	return
}

func LoadCertFromEnv(certEnv, keyEnv string) (certificate *x509.Certificate, privateKey any) {
	cert, err := tls.X509KeyPair([]byte(os.Getenv(certEnv)), []byte(os.Getenv(keyEnv)))
	if err != nil {
		panic(err)
	}

	if certificate, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		panic(err)
	}
	privateKey = cert.PrivateKey
	return
}
