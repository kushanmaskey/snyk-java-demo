# MISCONFIGURATION: Overly permissive IAM policy — grants full AWS access
resource "aws_iam_policy" "app_policy" {
  name        = "snyk-demo-app-policy"
  description = "Application policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"           # MISCONFIGURATION: Wildcard — allows all actions
        Resource = "*"           # MISCONFIGURATION: Wildcard — on all resources
      }
    ]
  })
}

# MISCONFIGURATION: IAM role with no condition constraints
resource "aws_iam_role" "app_role" {
  name = "snyk-demo-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "app" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.app_policy.arn
}
