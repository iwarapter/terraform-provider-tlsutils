package sdkv2provider

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceTLSUtilsCertificate() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceTLSUtilsCertificateRead,
		Schema:      dataSourceTLSUtilsCertificateSchema(),
		Description: `Parses a PEM encoded certificate to make various attributes available`,
	}
}

func dataSourceTLSUtilsCertificateSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"content": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The content of the PEM encoded certificate",
		},
		"signature_algorithm": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "The algorithm used to sign the certificate.",
		},
		"public_key_algorithm": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "The key algorithm used to create the certificate.",
		},
		"serial_number": {
			Type:     schema.TypeString,
			Computed: true,
			Description: "Number that uniquely identifies the certificate with the CA's system. " +
				"The `format` function can be used to convert this _base 10_ number " +
				"into other bases, such as hex.",
		},
		"is_ca": {
			Type:        schema.TypeBool,
			Computed:    true,
			Description: "`true` if the certificate is of a CA (Certificate Authority).",
		},
		"version": {
			Type:        schema.TypeInt,
			Computed:    true,
			Description: "The version the certificate is in.",
		},
		"issuer": {
			Type:     schema.TypeString,
			Computed: true,
			Description: "Who verified and signed the certificate, roughly following " +
				"[RFC2253](https://tools.ietf.org/html/rfc2253).",
		},
		"subject": {
			Type:     schema.TypeString,
			Computed: true,
			Description: "The entity the certificate belongs to, roughly following " +
				"[RFC2253](https://tools.ietf.org/html/rfc2253).",
		},
		"not_before": {
			Type:     schema.TypeString,
			Computed: true,
			Description: "The time after which the certificate is valid, as an " +
				"[RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.",
		},
		"not_after": {
			Type:     schema.TypeString,
			Computed: true,
			Description: "The time until which the certificate is invalid, as an " +
				"[RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.",
		},
		"sha1_fingerprint": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "The SHA1 fingerprint of the public key of the certificate.",
		},
	}
}

func dataSourceTLSUtilsCertificateRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	content := d.Get("content")
	block, _ := pem.Decode([]byte(content.(string)))
	if block == nil {
		return diag.FromErr(fmt.Errorf("failed to decode pem content"))
	}
	if block.Type != "CERTIFICATE" {
		return diag.FromErr(fmt.Errorf("pem must be of type 'CERTIFICATE'"))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return diag.FromErr(fmt.Errorf("unable to parse the certificate %w", err))
	}

	if err := d.Set("signature_algorithm", cert.SignatureAlgorithm.String()); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("public_key_algorithm", cert.PublicKeyAlgorithm.String()); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("serial_number", cert.SerialNumber.String()); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("is_ca", cert.IsCA); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("version", cert.Version); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("issuer", cert.Issuer.String()); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("subject", cert.Subject.String()); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("not_before", cert.NotBefore.Format(time.RFC3339)); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("not_after", cert.NotAfter.Format(time.RFC3339)); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err := d.Set("sha1_fingerprint", fmt.Sprintf("%x", sha1.Sum(cert.Raw))); err != nil {
		diags = append(diags, diag.FromErr(err)...)
	}
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(time.Now().UTC().String())
	return nil
}
