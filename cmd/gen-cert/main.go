package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"time"

	"testcert"
)

var (
	rootCA  *x509.Certificate
	rootKey any
)

func init() {
	if v := os.Getenv("USE_ENV"); v != "" && v != "0" {
		rootCA, rootKey = testcert.LoadCertFromEnv(
			"TEST_CERT_SECRET_ROOT_CA",
			"TEST_CERT_SECRET_ROOT_KEY",
		)
		return
	}

	rootCA, rootKey = testcert.LoadCertFromFile("root.crt", "root.key")
}

func main() {
	var (
		key       = testcert.GenerateKey()
		cert      = testcert.GenerateCertificate()
		now       = time.Now().UTC()
		notBefore = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		notAfter  = notBefore.AddDate(0, 9, 0)
	)

	if rootCA.NotAfter.Unix() <= notAfter.Unix() {
		panic("rootCA is expired")
	}

	cert.Subject = pkix.Name{CommonName: "core-pb.test"}
	cert.DNSNames = []string{"core-pb.test", "*.core-pb.test", "test.localhost", "*.test.localhost", "*.test.x2ox.com"}
	cert.NotBefore = notBefore
	cert.NotAfter = notAfter
	cert.BasicConstraintsValid = true
	cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	rootDer, err := x509.CreateCertificate(rand.Reader, cert, rootCA, key.Public(), rootKey)
	if err != nil {
		panic(err)
	}

	if cert, err = x509.ParseCertificate(rootDer); err != nil {
		panic(err)
	}

	testcert.WriteCert(cert, "server.crt")
	testcert.WriteKey(key, "server.key")
}
