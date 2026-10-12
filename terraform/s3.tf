# MISCONFIGURATION: S3 bucket with no encryption, public access, no versioning
resource "aws_s3_bucket" "app_data" {
  bucket = "snyk-demo-app-data"
}

# MISCONFIGURATION: Public access block disabled — bucket is publicly accessible
resource "aws_s3_bucket_public_access_block" "app_data" {
  bucket = aws_s3_bucket.app_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# MISCONFIGURATION: No server-side encryption configured
# MISCONFIGURATION: No versioning enabled — data loss risk
# MISCONFIGURATION: No logging enabled

resource "aws_s3_bucket_acl" "app_data" {
  bucke   t = aws_s3_bucket.app_data.id
  acl    = "public-read"  # MISCONFIGURATION: World-readable bucket
}

# MISCONFIGURATION: Logging bucket also has no encryption or access controls
resource "aws_s3_bucket" "logs" {
  bucket = "snyk-demo-logs"
}
