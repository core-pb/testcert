package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"testcert"
)

func main() {
	var (
		key       = testcert.GenerateKey()
		cert      = testcert.GenerateCertificate()
		now       = time.Now().UTC()
		notBefore = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		notAfter  = notBefore.AddDate(14, 6, 4).Add(4*time.Minute + time.Second + time.Nanosecond)
	)
	cert.Subject = pkix.Name{CommonName: "Developer Trusted Root X2"}
	cert.NotBefore = notBefore
	cert.NotAfter = notAfter
	cert.BasicConstraintsValid = true
	cert.IsCA = true
	cert.MaxPathLen = -1
	cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	rootDer, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		panic(err)
	}

	if cert, err = x509.ParseCertificate(rootDer); err != nil {
		panic(err)
	}

	testcert.WriteCert(cert, "root.crt")
	testcert.WriteKey(key, "root.key")
}
