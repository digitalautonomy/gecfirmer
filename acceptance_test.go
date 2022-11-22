package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	xades "github.com/digitalautonomy/goxades_sri"
	"github.com/stretchr/testify/suite"
)

type acceptanceSuite struct {
	suite.Suite
}

func TestAcceptanceSuite(t *testing.T) {
	suite.Run(t, new(acceptanceSuite))
}

func getTestResourcesDirectory() string {
	wd, _ := os.Getwd()
	return filepath.Join(wd, "test_resources")
}

func getTestResourcePath(name string) string {
	return filepath.Join(getTestResourcesDirectory(), name)
}

func (s *acceptanceSuite) Test_simpleInvoiceSigning() {
	test1Cert := getTestResourcePath("test1_without_password.p12")
	unsignedInvoice1 := getTestResourcePath("unsigned_invoice1.xml")

	result := (&signer{}).signInvoiceWith(test1Cert, unsignedInvoice1)

	fmt.Println(result)
}

func (s *acceptanceSuite) Test_simpleInvoiceSigning_compareWithProject1() {
	sig := &signer{
		addIdentifiersFunc: func(ctx *xades.SigningContext) {
			ctx.SignatureId = "Signature620190"
			ctx.SignedInfoId = "Signature-SignedInfo133964"
			ctx.SignatureValueId = "SignatureValue984886"
			ctx.ObjectId = "Signature620190-Object935731"
			ctx.KeyInfoId = "Certificate1696448"
			ctx.SignedPropertiesId = "Signature620190-SignedProperties976134"
			ctx.ReferenceMainDocumentId = "Reference-ID-723328"
			ctx.ReferencePropertiesId = "SignedPropertiesID1014990"
			res, _ := time.Parse("2006-01-02T15:04:05", "2022-11-22T16:05:57")
			ctx.PropertiesContext.SigninigTime = res
		},
	}

	test1Cert := getTestResourcePath("test1_without_password.p12")
	unsignedInvoice1 := getTestResourcePath("unsigned_invoice1.xml")

	result := sig.signInvoiceWith(test1Cert, unsignedInvoice1)

	fmt.Println(result)
}
