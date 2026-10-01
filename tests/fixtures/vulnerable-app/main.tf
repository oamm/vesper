resource "aws_s3_bucket" "synthetic_public_bucket" {
  bucket = "synthetic-security-fixture-public"
  acl    = "public-read"
}