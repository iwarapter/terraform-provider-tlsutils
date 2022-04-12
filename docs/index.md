# TLS Utils Provider

The TLS Utils provider is a collection of helpful utils not available in the hashicorp/tls provider.

## Example Usage
Terraform 0.13 and later:
```hcl
# Configure the TLS Utils Provider
terraform {
  required_providers {
    tlsutils = {
      source = "iwarapter/tlsutils"
      version = "0.0.1"
    }
  }
}

provider "tlsutils" {}
```
Terraform 0.12 and earlier:
```hcl
# Configure the TLS Utils Provider
provider "tlsutils" {}
```
