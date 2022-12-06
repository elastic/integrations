variable "TEST_RUN_ID" {
  default = "detached"
}

provider "aws" {
  default_tags {
    tags = {
      environment  = var.ENVIRONMENT
      repo         = var.REPO
      branch       = var.BRANCH
      build        = var.BUILD_ID
      created_date = var.CREATED_DATE
    }
  }
}

resource "aws_redshift_cluster" "test_cluster" {
  cluster_identifier  = "elastic-package-test-${var.TEST_RUN_ID}"
  database_name       = "mydb"
  master_username     = "exampleuser"
  master_password     = "Mustbe8characters"
  node_type           = "dc2.large"
  cluster_type        = "single-node"
  skip_final_snapshot = "true"
}
