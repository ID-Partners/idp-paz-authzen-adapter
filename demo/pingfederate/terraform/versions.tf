terraform {
  required_version = ">= 1.5.0" # for `import {}` blocks

  required_providers {
    pingfederate = {
      source  = "pingidentity/pingfederate"
      version = "~> 1.5"
    }
  }
}
