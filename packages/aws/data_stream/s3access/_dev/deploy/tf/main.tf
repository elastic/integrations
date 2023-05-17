provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  region                      = "us-east-1"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    iam            = "http://localstack:4566"
    s3             = "http://localstack:4566"
    kms            = "http://localstack:4566"
    sqs            = "http://localstack:4566"
  }
}

variable "TEST_RUN_ID" {
  default = "detached"
}