resource "aws_db_instance" "app_db" {
  identifier        = "snyk-demo-db"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "appdb"
  username = "admin"
  password = var.db_password   # sourced from a variable, never hardcoded

  # Database is NOT reachable from the public internet
  publicly_accessible = false

  # Encrypt data at rest using AWS-managed key
  storage_encrypted = true

  # Keep 7 days of automated backups for recovery
  backup_retention_period = 7

  # Prevent accidental deletion
  deletion_protection = true

  # Automatically apply minor version patches (security fixes)
  auto_minor_version_upgrade = true

  # Multi-AZ for high availability and failover
  multi_az = true

  # Allow IAM roles to authenticate instead of static passwords
  iam_database_authentication_enabled = true

  skip_final_snapshot = false
}

variable "db_password" {
  description = "RDS master password — supply via environment variable TF_VAR_db_password or AWS Secrets Manager"
  type        = string
  sensitive   = true
}
