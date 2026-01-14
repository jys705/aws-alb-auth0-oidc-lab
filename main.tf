terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  # AWS SSO 프로필 지정이 필요한 경우 주석 해제
  # profile = "your-sso-profile-name"
}

# 데이터 소스: 기본 VPC 및 서브넷 조회
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# 보안 그룹: Application Load Balancer
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Security group for ALB with Auth0 OIDC authentication"
  vpc_id      = data.aws_vpc.default.id

  # HTTP 인바운드 규칙
  # 개발 및 테스트 환경에서 사용, 프로덕션 환경에서는 HTTPS로 리다이렉트 권장
  ingress {
    description = "HTTP from Internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS 인바운드 규칙
  ingress {
    description = "HTTPS from Internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # 아웃바운드 트래픽 허용
  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-alb-sg"
  }
}

# 보안 그룹: EC2 웹 서버
resource "aws_security_group" "web" {
  name        = "${var.project_name}-web-sg"
  description = "Security group for backend web server instances"
  vpc_id      = data.aws_vpc.default.id

  # ALB로부터의 HTTP 트래픽만 허용
  ingress {
    description     = "HTTP from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # SSH 접근 허용 (인스턴스 관리 및 트러블슈팅)
  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # 아웃바운드 트래픽 허용
  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-web-sg"
  }
}

# EC2 인스턴스: 백엔드 웹 서버
resource "aws_instance" "web" {
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = var.instance_type
  
  vpc_security_group_ids = [aws_security_group.web.id]
  
  user_data = <<-EOF
              #!/bin/bash
              # Apache HTTP 서버 초기화 및 설정
              yum update -y
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              
              # 인증 성공 페이지 생성
              cat > /var/www/html/index.html <<'HTML'
              <!DOCTYPE html>
              <html lang="ko">
              <head>
                  <meta charset="UTF-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1.0">
                  <title>ALB + Auth0 연동 테스트</title>
                  <style>
                      body {
                          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                          display: flex;
                          justify-content: center;
                          align-items: center;
                          min-height: 100vh;
                          margin: 0;
                          padding: 20px;
                      }
                      .container {
                          background: white;
                          padding: 40px;
                          border-radius: 20px;
                          box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                          max-width: 600px;
                          text-align: center;
                      }
                      h1 {
                          color: #667eea;
                          margin-bottom: 20px;
                      }
                      .success {
                          background: #10b981;
                          color: white;
                          padding: 15px;
                          border-radius: 10px;
                          margin: 20px 0;
                          font-weight: bold;
                      }
                      .info {
                          background: #f3f4f6;
                          padding: 20px;
                          border-radius: 10px;
                          margin: 20px 0;
                          text-align: left;
                      }
                      .info h3 {
                          color: #667eea;
                          margin-top: 0;
                      }
                      .badge {
                          display: inline-block;
                          background: #667eea;
                          color: white;
                          padding: 5px 15px;
                          border-radius: 20px;
                          font-size: 14px;
                          margin: 5px;
                      }
                  </style>
              </head>
              <body>
                  <div class="container">
                      <h1>🎉 인증 성공!</h1>
                      <div class="success">
                          ✅ Auth0 OIDC 인증을 통과했습니다
                      </div>
                      <div class="info">
                          <h3>🔐 제로 트러스트 아키텍처</h3>
                          <p><strong>인증 흐름:</strong></p>
                          <ol style="text-align: left;">
                              <li>사용자 → ALB 접근 시도</li>
                              <li>ALB → Auth0로 리다이렉트</li>
                              <li>Auth0 로그인 페이지에서 인증</li>
                              <li>Auth0 → ALB로 토큰 전달</li>
                              <li>ALB → 토큰 검증 후 백엔드 접근 허용</li>
                          </ol>
                      </div>
                      <div class="info">
                          <h3>📋 구현된 보안 기능</h3>
                          <span class="badge">OIDC</span>
                          <span class="badge">Zero Trust</span>
                          <span class="badge">ALB 인증</span>
                          <span class="badge">Auth0</span>
                      </div>
                      <p style="color: #6b7280; font-size: 14px; margin-top: 30px;">
                          이 페이지는 인증된 사용자만 볼 수 있습니다.<br/>
                          <strong>실습 프로젝트:</strong> EKS Integrated Security Architecture v1.0
                      </p>
                  </div>
              </body>
              </html>
              HTML
              EOF

  tags = {
    Name = "${var.project_name}-web-server"
  }
}

# 타겟 그룹: 웹 서버를 위한 ALB 타겟 그룹
resource "aws_lb_target_group" "web" {
  name     = "${var.project_name}-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.default.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/"
    matcher             = "200"
  }

  tags = {
    Name = "${var.project_name}-tg"
  }
}

# 타겟 그룹 연결: EC2 인스턴스를 타겟 그룹에 등록
resource "aws_lb_target_group_attachment" "web" {
  target_group_arn = aws_lb_target_group.web.arn
  target_id        = aws_instance.web.id
  port             = 80
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.default.ids

  enable_deletion_protection = false

  tags = {
    Name = "${var.project_name}-alb"
  }
}

# HTTP 리스너: HTTPS를 사용하지 않는 요청에 대한 고정 응답
# 참고: ALB fixed_response는 1024자 제한이 있음
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    
    fixed_response {
      content_type = "text/html"
      message_body = <<-HTML
<!DOCTYPE html>
<html>
<head><title>HTTPS Required</title>
<style>body{font-family:Arial;background:#667eea;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.msg{background:#fff;padding:30px;border-radius:10px;text-align:center}h1{color:#ef4444}</style>
</head>
<body><div class="msg"><h1>⚠️ HTTPS Required</h1><p>이 애플리케이션은 HTTPS 연결이 필요합니다.</p><p><small>HTTPS 리스너 설정 후 Auth0 OIDC 인증을 사용할 수 있습니다.</small></p></div></body>
</html>
      HTML
      status_code  = "200"
    }
  }
}

# HTTPS 리스너 설정
# OIDC 인증이 포함된 HTTPS를 활성화하려면 아래 블록의 주석을 해제하고 설정
# 사전 요구사항:
# - ACM 인증서 ARN 제공 필요
# - Auth0 애플리케이션 자격 증명 설정 필요
# 
# resource "aws_lb_listener" "https" {
#   load_balancer_arn = aws_lb.main.arn
#   port              = "443"
#   protocol          = "HTTPS"
#   ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
#   certificate_arn   = var.acm_certificate_arn
#
#   default_action {
#     type = "authenticate-oidc"
#
#     authenticate_oidc {
#       authorization_endpoint = "https://${var.auth0_domain}/authorize"
#       client_id              = var.auth0_client_id
#       client_secret          = var.auth0_client_secret
#       issuer                 = "https://${var.auth0_domain}/"
#       token_endpoint         = "https://${var.auth0_domain}/oauth/token"
#       user_info_endpoint     = "https://${var.auth0_domain}/userinfo"
#     }
#   }
#
#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.web.arn
#   }
# }
