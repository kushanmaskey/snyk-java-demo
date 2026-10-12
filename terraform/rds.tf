# MISCONFIGURATION: RDS with no encryption, public access, no backups, no deletion protection
resource "aws_db_instance" "app_db" {
  identifier        = "snyk-demo-db"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "appdb"
  username = "admin"
  password = "SuperSecret123!"  # MISCONFIGURATION: Hardcoded credentials

  # MISCONFIGURATION: Database publicly accessible from internet
  publicly_accessible = true

  # MISCONFIGURATION: Storage not encrypted
  storage_encrypted = false

  # MISCONFIGURATION: Automated backups disabled
  backup_retention_period = 0

  # MISCONFIGURATION: No deletion protection
  deletion_protection = false

  # MISCONFIGURATION: Minor version upgrades disabled
  auto_minor_version_upgrade = false

  # MISCONFIGURATION: No Multi-AZ for high availability
  multi_az = false

  skip_final_snapshot = true
}
