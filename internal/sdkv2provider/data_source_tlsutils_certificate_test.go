package sdkv2provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAcc_dataSourceTLSUtilsCertificate(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{

				Config: `
					data "tlsutils_certificate" "test" {
					  content = file("testdata/certificate.pem")
					}
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.tlsutils_certificate.test", "signature_algorithm", "SHA256-RSA"),
					resource.TestCheckResourceAttr("data.tlsutils_certificate.test", "public_key_algorithm", "RSA"),
					resource.TestCheckResourceAttr("data.tlsutils_certificate.test", "serial_number", "266244246501122064554217434340898012243"),
					resource.TestCheckResourceAttr("data.tlsutils_certificate.test", "is_ca", "false"),
					resource.TestCheckResourceAttr("data.tlsutils_certificate.test", "version", "3"),
					resource.TestCheckResourceAttr("data.tlsutils_certificate.test", "issuer", "CN=Root CA,O=Test Org,L=Here"),
					resource.TestCheckResourceAttr("data.tlsutils_certificate.test", "subject", "CN=Child Cert,O=Child Co.,L=Everywhere"),
					resource.TestCheckResourceAttr("data.tlsutils_certificate.test", "not_before", "2019-11-08T09:01:36Z"),
					resource.TestCheckResourceAttr("data.tlsutils_certificate.test", "not_after", "2019-11-08T19:01:36Z"),
					resource.TestCheckResourceAttr("data.tlsutils_certificate.test", "sha1_fingerprint", "61b65624427d75b61169100836904e44364df817"),
				),
			},
			{
				Config: `
					data "tlsutils_certificate" "test" {
					  content = "not a pem"
					}
				`,
				ExpectError: regexp.MustCompile("failed to decode pem content"),
			},
			{
				Config: `
					data "tlsutils_certificate" "test" {
					  content = file("testdata/private.pem")
					}
				`,
				ExpectError: regexp.MustCompile("pem must be of type 'CERTIFICATE'"),
			},
		},
	})
}
