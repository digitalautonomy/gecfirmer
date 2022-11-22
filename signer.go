package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/rand"

	"github.com/beevik/etree"
	xades "github.com/digitalautonomy/goxades_sri"
	dsig "github.com/russellhaering/goxmldsig"
	"golang.org/x/crypto/pkcs12"
)

func (s *signer) readCertificateAndKey(certPath string) *xades.MemoryX509KeyStore {
	p12, _ := ioutil.ReadFile(certPath)
	blocks, _ := pkcs12.ToPEM(p12, "")

	var endUserKey *rsa.PrivateKey

	var endUserCert *x509.Certificate
	var endUserCertBytes []byte

	var certChain []*x509.Certificate

	for _, b := range blocks {
		if b.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(b.Bytes)
			err = err
			if cert.IsCA {
				certChain = append(certChain, cert)
			} else {
				endUserCert = cert
				endUserCertBytes = b.Bytes
			}
		} else if b.Type == "PRIVATE KEY" {
			key, err := x509.ParsePKCS1PrivateKey(b.Bytes)
			err = err
			endUserKey = key
		}
	}

	certChain = certChain

	return &xades.MemoryX509KeyStore{
		PrivateKey: endUserKey,
		Cert:       endUserCert,
		CertBinary: endUserCertBytes,
	}
}

func (s *signer) canonicalSerialize(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())

	doc.WriteSettings = etree.WriteSettings{
		CanonicalAttrVal: true,
		CanonicalEndTags: true,
		CanonicalText:    true,
	}

	return doc.WriteToBytes()
}

const randomIdentifierSize = 1000000

func (s *signer) addRandomIdentifiersFrom(intn func(int) int) func(*xades.SigningContext) {
	r := func() int {
		return intn(randomIdentifierSize)
	}

	return func(ctx *xades.SigningContext) {
		ctx.SignatureId = fmt.Sprintf("Signature%06d", r())
		ctx.SignedInfoId = fmt.Sprintf("Signature-SignedInfo%06d", r())
		ctx.SignatureValueId = fmt.Sprintf("SignatureValue%06d", r())
		ctx.ObjectId = fmt.Sprintf("%s-Object%06d", ctx.SignatureId, r())
		ctx.KeyInfoId = fmt.Sprintf("Certificate%06d", r())
		ctx.SignedPropertiesId = fmt.Sprintf("%s-SignedProperties%06d", ctx.SignatureId, r())
		ctx.ReferenceMainDocumentId = fmt.Sprintf("Reference-ID-%06d", r())
		ctx.ReferencePropertiesId = fmt.Sprintf("SignedPropertiesID%06d", r())
	}
}

type signer struct {
	addIdentifiersFunc func(*xades.SigningContext)
}

func (s *signer) addIdentifiers(ctx *xades.SigningContext) {
	if s.addIdentifiersFunc != nil {
		s.addIdentifiersFunc(ctx)
	} else {
		s.addRandomIdentifiersFrom(rand.Intn)(ctx)
	}
}

func (s *signer) signInvoiceWith(certPath, xmlPath string) string {
	doc := etree.NewDocument()
	doc.ReadFromFile(xmlPath)

	keyStore := s.readCertificateAndKey(certPath)

	canonicalizer := dsig.MakeC14N10RecCanonicalizer()
	signContext := xades.SigningContext{
		DataContext: xades.SignedDataContext{
			Canonicalizer: canonicalizer,
			Hash:          crypto.SHA1,
			ReferenceURI:  "#comprobante",
			IsEnveloped:   true,
		},
		PropertiesContext: xades.SignedPropertiesContext{
			Canonicalizer: canonicalizer,
			Hash:          crypto.SHA1,
		},
		Canonicalizer:                     canonicalizer,
		Hash:                              crypto.SHA1,
		KeyStore:                          *keyStore,
		DsigNamespacePrefix:               "ds",
		EtsiNamespacePrefix:               "etsi",
		EtsiNamespaceAtTopLevel:           true,
		IncludeKeyValue:                   true,
		IncludeSignedDataObjectProperties: true,
		SignedDataObjectDescription:       "contenido comprobante",
		ReferenceDataLast:                 true,
		ReferenceCertificate:              true,
		ReferenceAvoidTransformElements:   true,
	}

	s.addIdentifiers(&signContext)

	signature, _ := xades.CreateSignature(doc.Root(), &signContext)

	doc.Root().AddChild(signature)

	b, _ := s.canonicalSerialize(doc.Root())

	return string(b)
}
