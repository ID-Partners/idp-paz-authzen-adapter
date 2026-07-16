terraform {
  required_version = ">= 1.5"
  required_providers {
    davinci = {
      source  = "pingidentity/davinci"
      version = "~> 0.4"
    }
  }
}
