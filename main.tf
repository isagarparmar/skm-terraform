provider "aws" {
  region = "ca-central-1"
}

variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

variable "subnet_az" {
  default = ["ca-central-1a", "ca-central-1b"]
}

variable "public_subnet_cidrs" {
  default = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_web_subnet_cidrs" {
  default = ["10.0.32.0/24", "10.0.33.0/24"]
}

variable "private_server_subnet_cidrs" {
  default = ["10.0.64.0/24", "10.0.65.0/24"]
}

variable "private_db_subnet_cidrs" {
  default = ["10.0.96.0/24", "10.0.97.0/24"]
}

# Create a VPC
resource "aws_vpc" "skm_vpc" {
  cidr_block           = var.vpc_cidr
  instance_tenancy     = "default"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "skm_vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "internetgateway" {
  vpc_id = aws_vpc.skm_vpc.id
  tags = {
    Name = "internetgateway"
  }
}

# Public Subnet
resource "aws_subnet" "public_subnet" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.skm_vpc.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.subnet_az[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "public_subnet${count.index}"
  }
}

# Public Route Table
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.skm_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internetgateway.id
  }
  tags = {
    Name = "public_rt"
  }
}

# Public Route Table association
resource "aws_route_table_association" "public_rt_assoc" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public_subnet[count.index].id
  route_table_id = aws_route_table.public_rt.id
}

# Allocate an Elastic IP
resource "aws_eip" "nat_eip" {
  count = 2
  tags = {
    Name = "nat_eip_${count.index + 1}"
  }
}

# Create NAT Gateway
resource "aws_nat_gateway" "natgateway" {
  count         = 2
  allocation_id = aws_eip.nat_eip[count.index].id
  subnet_id     = aws_subnet.public_subnet[count.index].id
  tags = {
    Name = "natgateway_${count.index + 1}"
  }
  depends_on = [aws_internet_gateway.internetgateway]
}

# Private Subnet for web
resource "aws_subnet" "web_private_subnet" {
  count             = length(var.private_web_subnet_cidrs)
  vpc_id            = aws_vpc.skm_vpc.id
  cidr_block        = var.private_web_subnet_cidrs[count.index]
  availability_zone = var.subnet_az[count.index]
  tags = {
    Name = "web_private_subnet${count.index}"
  }
}

# Private Route Table for web
resource "aws_route_table" "web_private_rt" {
  count  = 2
  vpc_id = aws_vpc.skm_vpc.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.natgateway[count.index].id
  }
  tags = {
    Name = "web_private_rt_${count.index + 1}"
  }
  depends_on = [aws_nat_gateway.natgateway]
}

# Private Route Table association for web
resource "aws_route_table_association" "web_private_rt_assoc" {
  count          = 2
  subnet_id      = aws_subnet.web_private_subnet[count.index].id
  route_table_id = aws_route_table.web_private_rt[count.index].id
}

# Private Subnet for server
resource "aws_subnet" "server_private_subnet" {
  count             = length(var.private_server_subnet_cidrs)
  vpc_id            = aws_vpc.skm_vpc.id
  cidr_block        = var.private_server_subnet_cidrs[count.index]
  availability_zone = var.subnet_az[count.index]
  tags = {
    Name = "server_private_subnet${count.index}"
  }
}

# Private Route Table for server
resource "aws_route_table" "server_private_rt" {
  count  = 2
  vpc_id = aws_vpc.skm_vpc.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.natgateway[count.index].id
  }
  tags = {
    Name = "server_private_rt_${count.index + 1}"
  }
}

# Private Route Table association for server
resource "aws_route_table_association" "server_private_rt_assoc" {
  count          = 2
  subnet_id      = aws_subnet.server_private_subnet[count.index].id
  route_table_id = aws_route_table.server_private_rt[count.index].id
}

# Private Subnet for db
resource "aws_subnet" "db_private_subnet" {
  count             = length(var.private_db_subnet_cidrs)
  vpc_id            = aws_vpc.skm_vpc.id
  cidr_block        = var.private_db_subnet_cidrs[count.index]
  availability_zone = var.subnet_az[count.index]
  tags = {
    Name = "db_private_subnet${count.index}"
  }
}

# Private Route Table for db
resource "aws_route_table" "db_private_rt" {
  count  = 2
  vpc_id = aws_vpc.skm_vpc.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.natgateway[count.index].id
  }
  tags = {
    Name = "db_private_rt_${count.index + 1}"
  }
}

# Private Route Table association for db
resource "aws_route_table_association" "db_private_rt_assoc" {
  count          = 2
  subnet_id      = aws_subnet.db_private_subnet[count.index].id
  route_table_id = aws_route_table.db_private_rt[count.index].id
}

# Security Group for application load balancer external
resource "aws_security_group" "external_alb_sg" {
  name        = "external_alb_sg"
  description = "External ALB Security Group"
  vpc_id      = aws_vpc.skm_vpc.id
  tags = {
    Name    = "external_alb_sg"
    Purpose = "Accept internet trafic and forward it to frontend ecs security group"
  }
}

# Security Group allow http inbound rule for external alb, here the flow come from internet as req. on port 80
resource "aws_vpc_security_group_ingress_rule" "external_alb_http" {
  security_group_id = aws_security_group.external_alb_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

# Security Group allow all traffic outbound rule for external alb
resource "aws_vpc_security_group_egress_rule" "external_alb_all_out" {
  security_group_id = aws_security_group.external_alb_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# Security Group for frontend ECS
resource "aws_security_group" "frontend_ecs_sg" {
  name        = "frontend_ecs_sg"
  description = "Frontend ECS Tasks Security Group"
  vpc_id      = aws_vpc.skm_vpc.id
  tags = {
    Name    = "frontend_ecs_sg"
    Purpose = "Accept requests from external alg security group and forward it to internal alb security group"
  }
}

# Security Group allow http inbound rule for frontend ECS, here as the frontend is running on 3000 it will accepts req. on port 3000
resource "aws_vpc_security_group_ingress_rule" "frontend_ecs_from_alb" {
  security_group_id            = aws_security_group.frontend_ecs_sg.id
  referenced_security_group_id = aws_security_group.external_alb_sg.id
  from_port                    = 3000
  to_port                      = 3000
  ip_protocol                  = "tcp"
}

# Security Group allow all traffic outbound rule for frontend ECS
resource "aws_vpc_security_group_egress_rule" "frontend_ecs_all_out" {
  security_group_id = aws_security_group.frontend_ecs_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# Security Group for application load balancer internal
resource "aws_security_group" "internal_alb_sg" {
  name        = "internal_alb_sg"
  description = "Internal ALB Security Group"
  vpc_id      = aws_vpc.skm_vpc.id
  tags = {
    Name    = "internal_alb_sg"
    Purpose = "Accepts frontend requests and forward it to backend ecs security group"
  }
}

# Security Group allow http inbound rule for internal alb, as backend is running on port 5000 forntend will req. to port 5000 through alb
resource "aws_vpc_security_group_ingress_rule" "alb_http_1" {
  security_group_id            = aws_security_group.internal_alb_sg.id
  referenced_security_group_id = aws_security_group.frontend_ecs_sg.id
  from_port                    = 4001
  to_port                      = 4001
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_http_2" {
  security_group_id            = aws_security_group.internal_alb_sg.id
  referenced_security_group_id = aws_security_group.frontend_ecs_sg.id
  from_port                    = 4002
  to_port                      = 4002
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_http_3" {
  security_group_id            = aws_security_group.internal_alb_sg.id
  referenced_security_group_id = aws_security_group.frontend_ecs_sg.id
  from_port                    = 4003
  to_port                      = 4003
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_http_4" {
  security_group_id            = aws_security_group.internal_alb_sg.id
  referenced_security_group_id = aws_security_group.frontend_ecs_sg.id
  from_port                    = 4004
  to_port                      = 4004
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_http_5" {
  security_group_id            = aws_security_group.internal_alb_sg.id
  referenced_security_group_id = aws_security_group.frontend_ecs_sg.id
  from_port                    = 4005
  to_port                      = 4005
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_http_6" {
  security_group_id            = aws_security_group.internal_alb_sg.id
  referenced_security_group_id = aws_security_group.frontend_ecs_sg.id
  from_port                    = 4006
  to_port                      = 4006
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_http_7" {
  security_group_id            = aws_security_group.internal_alb_sg.id
  referenced_security_group_id = aws_security_group.frontend_ecs_sg.id
  from_port                    = 5000
  to_port                      = 5000
  ip_protocol                  = "tcp"
}

# Security Group allow all traffic outbound rule for internal alb
resource "aws_vpc_security_group_egress_rule" "alb_all_out" {
  security_group_id = aws_security_group.internal_alb_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# Security Group for backend ECS
resource "aws_security_group" "backend_ecs_sg" {
  name        = "backend_ecs_sg"
  description = "Backend ECS Tasks Security Group"
  vpc_id      = aws_vpc.skm_vpc.id
  tags = {
    Name    = "backend_ecs_sg"
    Purpose = "Accepts request made by frontend to backend from internal alb security group"
  }
}

# Security Group allow http inbound rule for backend ECS, internal alb will req. to backend on its port 5000
resource "aws_vpc_security_group_ingress_rule" "backend_ecs_from_alb_1" {
  security_group_id            = aws_security_group.backend_ecs_sg.id
  referenced_security_group_id = aws_security_group.internal_alb_sg.id
  from_port                    = 4001
  to_port                      = 4001
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "backend_ecs_from_alb_2" {
  security_group_id            = aws_security_group.backend_ecs_sg.id
  referenced_security_group_id = aws_security_group.internal_alb_sg.id
  from_port                    = 4002
  to_port                      = 4002
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "backend_ecs_from_alb_3" {
  security_group_id            = aws_security_group.backend_ecs_sg.id
  referenced_security_group_id = aws_security_group.internal_alb_sg.id
  from_port                    = 4003
  to_port                      = 4003
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "backend_ecs_from_alb_4" {
  security_group_id            = aws_security_group.backend_ecs_sg.id
  referenced_security_group_id = aws_security_group.internal_alb_sg.id
  from_port                    = 4004
  to_port                      = 4004
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "backend_ecs_from_alb_5" {
  security_group_id            = aws_security_group.backend_ecs_sg.id
  referenced_security_group_id = aws_security_group.internal_alb_sg.id
  from_port                    = 4005
  to_port                      = 4005
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "backend_ecs_from_alb_6" {
  security_group_id            = aws_security_group.backend_ecs_sg.id
  referenced_security_group_id = aws_security_group.internal_alb_sg.id
  from_port                    = 4006
  to_port                      = 4006
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "backend_ecs_from_alb_7" {
  security_group_id            = aws_security_group.backend_ecs_sg.id
  referenced_security_group_id = aws_security_group.internal_alb_sg.id
  from_port                    = 5000
  to_port                      = 5000
  ip_protocol                  = "tcp"
}

# Security Group allow all traffic outbound rule for backend ECS
resource "aws_vpc_security_group_egress_rule" "backend_ecs_all_out" {
  security_group_id = aws_security_group.backend_ecs_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# Security Group for RDS
resource "aws_security_group" "db_sg" {
  name        = "db_sg"
  description = "Security group for RDS PostgreSQL"
  vpc_id      = aws_vpc.skm_vpc.id
  tags = {
    Name = "db_sg"
  }
}

# Security Group allow http inbound rule
resource "aws_vpc_security_group_ingress_rule" "db_allow_ecs" {
  security_group_id            = aws_security_group.db_sg.id
  referenced_security_group_id = aws_security_group.backend_ecs_sg.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# Security Group allow all traffic outbound rule
resource "aws_vpc_security_group_egress_rule" "db_all_out" {
  security_group_id = aws_security_group.db_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# Application load balancer for frontend
resource "aws_lb" "frontend-alb" {
  name                       = "frontend-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.external_alb_sg.id]
  subnets                    = aws_subnet.public_subnet[*].id
  enable_deletion_protection = false
  tags = {
    Name = "frontend-alb"
  }
}

# Load balancer target group for frontend
resource "aws_lb_target_group" "frontend-lb-tg" {
  name        = "frontend-lb-tg"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.skm_vpc.id
  target_type = "ip"

  health_check {
    path                = "/"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = {
    Name = "frontend-lb-tg"
  }
}

# Load balancer listner for frontend
resource "aws_lb_listener" "frontend_lb_listener" {
  load_balancer_arn = aws_lb.frontend-alb.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend-lb-tg.arn
  }
}

# Microservices definition
locals {
  microservices = [
    { name = "admin", port = 4001 },
    { name = "auth", port = 4002 },
    { name = "household", port = 4003 },
    { name = "recipe", port = 4004 },
    { name = "store", port = 4005 },
    { name = "user", port = 4006 },
    { name = "seeder", port = 5000 }
  ]
}

# Application load balancer for backend
resource "aws_lb" "backend-alb" {
  name                       = "backend-alb"
  internal                   = true
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.internal_alb_sg.id]
  subnets                    = aws_subnet.server_private_subnet[*].id
  enable_deletion_protection = false

  tags = {
    Name = "backend-alb"
  }
}

# Load balancer target group for backend microservices
resource "aws_lb_target_group" "backend-lb-tg" {
  count       = length(local.microservices)
  name        = "backend-tg-${local.microservices[count.index].name}"
  port        = local.microservices[count.index].port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.skm_vpc.id
  target_type = "ip"

  health_check {
    path                = "/"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = {
    Name = "backend-tg-${local.microservices[count.index].name}"
  }
}

# Load balancer listner for backend microservices
resource "aws_lb_listener" "backend_lb_listener" {
  count             = length(local.microservices)
  load_balancer_arn = aws_lb.backend-alb.arn
  port              = local.microservices[count.index].port
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend-lb-tg[count.index].arn
  }
}

# ECS Cluster for frontend
resource "aws_ecs_cluster" "frontend_ecs_cluster" {
  name = "frontend_ecs_cluster"
}

# ECS Task defination for frontend
resource "aws_ecs_task_definition" "frontend_ecs_task" {
  family                   = "frontend_ecs_task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  container_definitions = jsonencode([
    {
      name  = "frontend-service"
      image = "851725659285.dkr.ecr.ca-central-1.amazonaws.com/skm-frontend:latest"
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_frontend_logs.name
          "awslogs-region"        = "ca-central-1"
          "awslogs-stream-prefix" = "ecs"
        }
      }
      portMappings = [
        {
          containerPort = 3000
          hostPort      = 3000
          protocol      = "tcp"
        }
      ]
      environment = [
        { name = "REACT_APP_AUTH_API_BASE_URL", value = "http://${aws_lb.backend-alb.dns_name}:4002/" },
        { name = "REACT_APP_HOUSE_HOLD_API_BASE_URL", value = "http://${aws_lb.backend-alb.dns_name}:4003/" },
        { name = "REACT_APP_RECIPE_API_BASE_URL", value = "http://${aws_lb.backend-alb.dns_name}:4004/" },
        { name = "REACT_APP_STORE_API_BASE_URL", value = "http://${aws_lb.backend-alb.dns_name}:4005/" },
        { name = "REACT_APP_USERS_API_BASE_URL", value = "http://${aws_lb.backend-alb.dns_name}:4006/" },
      ]
    }
  ])
}

# ECS Service for frontend
resource "aws_ecs_service" "frontend_ecs" {
  name            = "frontend_ecs"
  cluster         = aws_ecs_cluster.frontend_ecs_cluster.id
  task_definition = aws_ecs_task_definition.frontend_ecs_task.arn
  launch_type     = "FARGATE"
  desired_count   = 2

  load_balancer {
    target_group_arn = aws_lb_target_group.frontend-lb-tg.arn
    container_name   = "frontend-service"
    container_port   = 3000
  }

  network_configuration {
    security_groups = [aws_security_group.frontend_ecs_sg.id]
    subnets         = aws_subnet.web_private_subnet[*].id
  }

  depends_on = [
    aws_lb.frontend-alb,
    aws_ecs_cluster.frontend_ecs_cluster
  ]
}

# ECS Cluster for backend
resource "aws_ecs_cluster" "backend_ecs_cluster" {
  name = "backend_ecs_cluster"
}

# Fetch env variables from paramter store
data "aws_ssm_parameter" "node_env" {
  name = "/skm/nodejs_env"
}
data "aws_ssm_parameter" "name" {
  name = "/skm/name"
}
data "aws_ssm_parameter" "enc_key" {
  name = "/skm/enc_key"
}
data "aws_ssm_parameter" "enc_iv" {
  name = "/skm/enc_iv"
}
data "aws_ssm_parameter" "jwt_secret" {
  name = "/skm/jwt_secret"
}
data "aws_ssm_parameter" "cipher_secret" {
  name = "/skm/cipher_secret"
}
data "aws_ssm_parameter" "jwt_refresh_secret" {
  name = "/skm/jwt_refresh_secret"
}
data "aws_ssm_parameter" "jwt_ttl" {
  name = "/skm/jwt_ttl"
}
data "aws_ssm_parameter" "jwt_refresh_ttl" {
  name = "/skm/jwt_refresh_ttl"
}
data "aws_ssm_parameter" "smtp_host" {
  name = "/skm/smtp_host"
}
data "aws_ssm_parameter" "smtp_port" {
  name = "/skm/smtp_port"
}
data "aws_ssm_parameter" "smtp_from" {
  name = "/skm/smtp_from"
}
data "aws_ssm_parameter" "smtp_user" {
  name = "/skm/smtp_user"
}
data "aws_ssm_parameter" "smtp_pass" {
  name = "/skm/smtp_pass"
}
data "aws_ssm_parameter" "dev_email" {
  name = "/skm/dev_email"
}
data "aws_ssm_parameter" "s3_bucket_name" {
  name = "/skm/s3_bucket_name"
}
data "aws_ssm_parameter" "s3_secret" {
  name = "/skm/s3_secret"
}
data "aws_ssm_parameter" "s3_access_key" {
  name = "/skm/s3_access_key"
}
data "aws_ssm_parameter" "s3_region" {
  name = "/skm/s3_region"
}
data "aws_ssm_parameter" "s3_ingd_folder" {
  name = "/skm/s3_ingd_folder"
}
data "aws_ssm_parameter" "s3_recipe_folder" {
  name = "/skm/s3_recipe_folder"
}
data "aws_ssm_parameter" "mongo_user" {
  name = "/skm/mongo_user"
}
data "aws_ssm_parameter" "mongo_pass" {
  name = "/skm/mongo_pass"
}
data "aws_ssm_parameter" "mongo_host" {
  name = "/skm/mongo_host"
}
data "aws_ssm_parameter" "mongo_port" {
  name = "/skm/mongo_port"
}
data "aws_ssm_parameter" "mongo_db_name" {
  name = "/skm/mongo_db_name"
}

# ECS Task defination for backend
resource "aws_ecs_task_definition" "backend_ecs_task" {
  count                    = length(local.microservices)
  family                   = "${local.microservices[count.index].name}_ecs_task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  container_definitions = jsonencode([
    {
      name  = "${local.microservices[count.index].name}-service"
      image = "851725659285.dkr.ecr.ca-central-1.amazonaws.com/skm-${local.microservices[count.index].name}:latest"
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_service_logs[count.index].name
          "awslogs-region"        = "ca-central-1"
          "awslogs-stream-prefix" = "ecs"
        }
      }
      portMappings = [
        {
          containerPort = local.microservices[count.index].port
          hostPort      = local.microservices[count.index].port
          protocol      = "tcp"
        }
      ]
      environment = [
        {
          name  = "PORT",
          value = tostring(local.microservices[count.index].port)
        },
        {
          name  = "LOG_PATH",
          value = "./logs/"
        },
        {
          name  = "BASE_URL",
          value = "http://${aws_lb.backend-alb.dns_name}:${local.microservices[count.index].port}"
        },
        {
          name  = "NODE_ENV",
          value = data.aws_ssm_parameter.node_env.value
        },
        {
          name  = "NAME",
          value = data.aws_ssm_parameter.name.value
        },
        {
          name  = "ENC_KEY",
          value = data.aws_ssm_parameter.enc_key.value
        },
        {
          name  = "ENC_IV",
          value = data.aws_ssm_parameter.enc_iv.value
        },
        {
          name  = "JWT_SECRET",
          value = data.aws_ssm_parameter.jwt_secret.value
        },
        {
          name  = "CIPHER_SECRET",
          value = data.aws_ssm_parameter.cipher_secret.value
        },
        {
          name  = "JWT_REFERSH_SECRET",
          value = data.aws_ssm_parameter.jwt_refresh_secret.value
        },
        {
          name  = "JWT_TTL",
          value = data.aws_ssm_parameter.jwt_ttl.value
        },
        {
          name  = "JWT_REFERSH_TTL",
          value = data.aws_ssm_parameter.jwt_refresh_ttl.value
        },
        {
          name  = "SMTP_HOST",
          value = data.aws_ssm_parameter.smtp_host.value
        },
        {
          name  = "SMTP_PORT",
          value = data.aws_ssm_parameter.smtp_port.value
        },
        {
          name  = "SMTP_FROM",
          value = data.aws_ssm_parameter.smtp_from.value
        },
        {
          name  = "SMTP_USER",
          value = data.aws_ssm_parameter.smtp_user.value
        },
        {
          name  = "SMTP_PASSWORD",
          value = data.aws_ssm_parameter.smtp_pass.value
        },
        {
          name  = "DEV_EMAILS",
          value = data.aws_ssm_parameter.dev_email.value
        },
        {
          name  = "S3_BUCKET_NAME",
          value = data.aws_ssm_parameter.s3_bucket_name.value
        },
        {
          name  = "S3_SECRET",
          value = data.aws_ssm_parameter.s3_secret.value
        },
        {
          name  = "S3_ACCESS_KEY",
          value = data.aws_ssm_parameter.s3_access_key.value
        },
        {
          name  = "S3_REGION",
          value = data.aws_ssm_parameter.s3_region.value
        },
        {
          name  = "S3_INGD_FOLDER",
          value = data.aws_ssm_parameter.s3_ingd_folder.value
        },
        {
          name  = "S3_RECIPE_FOLDER",
          value = data.aws_ssm_parameter.s3_recipe_folder.value
        },
        {
          name  = "MONGO_USER",
          value = data.aws_ssm_parameter.mongo_user.value
        },
        {
          name  = "MONGO_PASSWORD",
          value = data.aws_ssm_parameter.mongo_pass.value
        },
        {
          name  = "MONGO_HOST",
          value = data.aws_ssm_parameter.mongo_host.value
        },
        {
          name  = "MONGO_PORT",
          value = data.aws_ssm_parameter.mongo_port.value
        },
        {
          name  = "MONGO_NAME",
          value = data.aws_ssm_parameter.mongo_db_name.value
        },
        {
          name  = "DB_HOST",
          value = aws_rds_cluster.postgresql-rds-db.endpoint
        },
        {
          name  = "DB_PORT",
          value = "5432"
        },
        {
          name  = "DB_USER",
          value = "postgres"
        },
        {
          name  = "DB_PASSWORD",
          value = "cloudinfra123456789"
        },
        {
          name  = "DB_NAME",
          value = "smart_kitchen_helper"
        },
        {
          name  = "REDIS_URL",
          value = aws_elasticache_cluster.cache_cluster.cache_nodes[0].address
        },
        {
          name  = "REDIS_PORT",
          value = "6379"
        },
        {
          name  = "REDIS_PASSWORD",
          value = ""
        },
        {
          name  = "REDIS_USER",
          value = ""
        },
        {
          name  = "REDIS_TTL",
          value = "24h"
        }
      ]
    }
  ])
}

# ECS Service for backend
resource "aws_ecs_service" "backend_ecs" {
  count           = length(local.microservices)
  name            = "${local.microservices[count.index].name}_ecs"
  cluster         = aws_ecs_cluster.backend_ecs_cluster.id
  task_definition = aws_ecs_task_definition.backend_ecs_task[count.index].arn
  launch_type     = "FARGATE"
  desired_count   = local.microservices[count.index].name == "seeder" ? 1 : 2

  load_balancer {
    target_group_arn = aws_lb_target_group.backend-lb-tg[count.index].arn
    container_name   = "${local.microservices[count.index].name}-service"
    container_port   = local.microservices[count.index].port
  }

  network_configuration {
    security_groups = [aws_security_group.backend_ecs_sg.id]
    subnets         = aws_subnet.server_private_subnet[*].id
  }

  depends_on = [
    aws_lb.backend-alb,
    aws_ecs_cluster.backend_ecs_cluster
  ]
}

# Define Auto Scaling Target for frontend
resource "aws_appautoscaling_target" "frontend_ecs_scaling" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.frontend_ecs_cluster.name}/${aws_ecs_service.frontend_ecs.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = 2
  max_capacity       = 5
}

# Scaling Policy - frontend
resource "aws_appautoscaling_policy" "frontend_ecs_scaling_policy" {
  name               = "frontend_ecs_scaling_policy"
  service_namespace  = aws_appautoscaling_target.frontend_ecs_scaling.service_namespace
  resource_id        = aws_appautoscaling_target.frontend_ecs_scaling.resource_id
  scalable_dimension = aws_appautoscaling_target.frontend_ecs_scaling.scalable_dimension
  policy_type        = "TargetTrackingScaling"

  target_tracking_scaling_policy_configuration {
    target_value = 75.0
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    scale_out_cooldown = 60
    scale_in_cooldown  = 60
  }
}

# Define Auto Scaling Target for backend
resource "aws_appautoscaling_target" "backend_ecs_scaling" {
  count              = length(local.microservices)
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.backend_ecs_cluster.name}/${aws_ecs_service.backend_ecs[count.index].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = 2
  max_capacity       = 5

  depends_on = [
    aws_ecs_cluster.backend_ecs_cluster,
    aws_ecs_service.backend_ecs
  ]
}

# Scaling Policy
resource "aws_appautoscaling_policy" "backend_ecs_scaling_policy" {
  count              = length(local.microservices)
  name               = "backend_ecs_scaling_policy_${local.microservices[count.index].name}"
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.backend_ecs_cluster.name}/${aws_ecs_service.backend_ecs[count.index].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  policy_type        = "TargetTrackingScaling"

  target_tracking_scaling_policy_configuration {
    target_value = 75.0
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    scale_out_cooldown = 60
    scale_in_cooldown  = 60
  }

  depends_on = [
    aws_appautoscaling_target.backend_ecs_scaling,
    aws_ecs_cluster.backend_ecs_cluster,
    aws_ecs_service.backend_ecs
  ]
}

# IAM Roles
resource "aws_iam_role" "ecs_execution_role" {
  name = "ecs_execution_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

# IAM Policy
resource "aws_iam_role_policy_attachment" "ecs_execution_role_policy" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
resource "aws_iam_role_policy_attachment" "ecs_cloudwatch_logs" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
}
# Parameter Store Access Policy
resource "aws_iam_role_policy" "ecs_parameter_store_access" {
  name = "ecs_parameter_store_access"
  role = aws_iam_role.ecs_execution_role.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameters",
          "kms:Decrypt"
        ]
        Resource = [
          "arn:aws:ssm:ca-central-1:851725659285:parameter/skm/*",
          "arn:aws:kms:ca-central-1:851725659285:key/a73726fe-e796-4a13-a88e-442bd878b6be"
        ]
      }
    ]
  })
}

# RDS Aurora PostgreSQL Cluster
resource "aws_rds_cluster" "postgresql-rds-db" {
  cluster_identifier      = "postgresql-rds-db"
  engine                  = "aurora-postgresql"
  engine_version          = "14.6"
  availability_zones      = ["ca-central-1a", "ca-central-1b"]
  database_name           = "smart_kitchen_helper"
  master_username         = "postgres"
  master_password         = "cloudinfra123456789"
  backup_retention_period = 35
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true

  vpc_security_group_ids = [aws_security_group.db_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name
}

# RDS Cluster Instance
resource "aws_rds_cluster_instance" "postgresql-rds-instance" {
  count              = 2
  identifier         = "postgresql-rds-instance-${count.index}"
  cluster_identifier = aws_rds_cluster.postgresql-rds-db.id
  instance_class     = "db.t3.medium"
  engine             = aws_rds_cluster.postgresql-rds-db.engine
  engine_version     = aws_rds_cluster.postgresql-rds-db.engine_version
}

# RDS Subnet group
resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = "rds_subnet_group"
  subnet_ids = aws_subnet.db_private_subnet[*].id
  tags = {
    Name = "PGSQL subnet group"
  }
}

# Elastic cache
resource "aws_elasticache_subnet_group" "cache_subnet_group" {
  name       = "cache-subnet-group"
  subnet_ids = aws_subnet.db_private_subnet[*].id

  tags = {
    Name = "cache-subnet-group"
  }
}

resource "aws_security_group" "cache_sg" {
  name        = "cache_sg"
  description = "Security group for ElastiCache"
  vpc_id      = aws_vpc.skm_vpc.id

  tags = {
    Name = "cache_sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "cache_ingress" {
  security_group_id            = aws_security_group.cache_sg.id
  referenced_security_group_id = aws_security_group.backend_ecs_sg.id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "cache_egress" {
  security_group_id = aws_security_group.cache_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_elasticache_cluster" "cache_cluster" {
  cluster_id           = "skm-redis"
  engine               = "redis"
  node_type            = "cache.t2.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis6.x"
  engine_version       = "6.x"
  subnet_group_name    = aws_elasticache_subnet_group.cache_subnet_group.name
  security_group_ids   = [aws_security_group.cache_sg.id]
  apply_immediately    = true
  tags = {
    Name = "skm-redis"
  }
}

# Logs
resource "aws_cloudwatch_log_group" "ecs_frontend_logs" {
  name              = "/ecs/frontend_ecs"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "ecs_service_logs" {
  count             = length(local.microservices)
  name              = "/ecs/${local.microservices[count.index].name}-logs"
  retention_in_days = 14
}

# Outputs
output "db_endpoint" {
  value = aws_rds_cluster.postgresql-rds-db.endpoint
}

output "alb_dns_name" {
  description = "Application load balancer dns name"
  value       = aws_lb.frontend-alb.dns_name
}

output "redis_cache_url" {
  value = aws_elasticache_cluster.cache_cluster.cache_nodes[0].address
}
