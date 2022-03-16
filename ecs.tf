locals {
  production_availability_zones = "us-east-1a"
}

#ECR repository to store our Docker images
resource "aws_ecr_repository" "web" {
  name                 = var.app_name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
resource "aws_iam_role_policy" "ecs_execution_role_policy" {
  name = "${var.app_name}-execution-role"
  role = aws_iam_role.ecs_execution_role.id

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role" "ecs_execution_role" {
  name = "${var.app_name}-role-policy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      },
    ]
  })
}


#ECS task definitions
# the task definition for the web service
resource "aws_ecs_task_definition" "web" {
  family                   = var.app_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_execution_role.arn
  container_definitions = jsonencode([
    {
      name      = "${var.app_name}"
      image     = "${var.account}.dkr.ecr.${var.region}.amazonaws.com/${var.app_name}"
      cpu       = 1024
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
        }
      ],
      environment = [
        # {name = "AUTH_TOKEN", value = "${var.AUTH_TOKEN}"},
        { name = "AWS_ACCESS_KEY_ID", value = "${var.awsAccessKeyID}" },
        { name = "AWS_SECRET_ACCESS_KEY", value = "${var.awsSecretAccessKeyID}" },
        # {name = "aws.region", value = "${var.awsRegion}"},
        # {name = "aws.s3.bucket.name.update", value = "${var.awsS3BucketNameUpdate}"},
        { name = "PG_HOST", value = "${var.PG_HOST}" },
        { name = "PG_PASS", value = "${var.PG_PASS}" },
        { name = "PG_USER", value = "${var.PG_USER}" }
      ],
      logConfiguration = {
        logDriver = "awsfirelens",
        options = {
          Name     = "newrelic",
          endpoint = "https://log-api.newrelic.com/log/v1"
        },
        secretOptions = [
          { name = "apiKey", valueFrom = "arn:aws:ssm:us-east-1:050978480733:parameter/YOURCOMPANY/dev/newrelic/licenseKey" }
        ],
      }
    },
    {
      name      = "log_router"
      image     = "050978480733.dkr.ecr.us-east-1.amazonaws.com/newrelic/logging-firelens-fluentbit"
      essential = true
      firelensConfiguration = {
        type = "fluentbit",
        options = {
          enable-ecs-log-metadata = "true"
        }
      }
    }
  ])

}


#App Load Balancer
resource "random_id" "target_group_sufix" {
  byte_length = 2
}

resource "aws_alb_target_group" "alb_target_group" {
  name        = var.app_name
  port        = 80
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  lifecycle {
    create_before_destroy = true
  }
}


resource "aws_lb_listener_rule" "static" {
  listener_arn = var.listenerArn
  priority     = 20

  action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.alb_target_group.arn
  }

  condition {
    host_header {
      values = ["${var.app_name_host}.dev.YOURCOMPANY"]
    }
  }
}


#ECS service
#Security Group for ECS
resource "aws_security_group" "ecs_service" {
  vpc_id      = var.vpc_id
  name        = "${var.sg_name}-sg"
  description = "Allow egress from container"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["172.26.0.0/16"]
  }
}

resource "aws_ecs_service" "web" {
  name            = var.app_name
  launch_type     = "FARGATE"
  cluster         = var.cluster_name
  task_definition = aws_ecs_task_definition.web.arn
  desired_count   = 1

  network_configuration {
    security_groups  = [aws_security_group.ecs_service.id]
    subnets          = var.subnets
    assign_public_ip = "false"

  }
  load_balancer {
    target_group_arn = aws_alb_target_group.alb_target_group.arn
    container_name   = var.app_name
    container_port   = 8080
  }
  depends_on = [aws_ecs_task_definition.web]
}
