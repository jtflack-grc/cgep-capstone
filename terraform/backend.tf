terraform {
  backend "s3" {
    bucket       = "cgep-capstone-tfstate-290993051335"
    key          = "cgep-capstone/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
