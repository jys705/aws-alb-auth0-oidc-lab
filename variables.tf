variable "aws_region" {
  description = "리소스 배포 대상 AWS 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "project_name" {
  description = "리소스 이름 지정 및 태깅에 사용되는 프로젝트 이름"
  type        = string
  default     = "alb-auth0-lab"
}

variable "instance_type" {
  description = "웹 서버에 사용할 EC2 인스턴스 타입"
  type        = string
  default     = "t2.micro"
}

# Auth0 설정
# 실제 값은 terraform.tfvars 파일에 입력
variable "auth0_domain" {
  description = "Auth0 도메인 (예: dev-xxxxx.us.auth0.com)"
  type        = string
  default     = ""
}

variable "auth0_client_id" {
  description = "Auth0 애플리케이션 클라이언트 ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "auth0_client_secret" {
  description = "Auth0 애플리케이션 클라이언트 시크릿"
  type        = string
  default     = ""
  sensitive   = true
}

variable "acm_certificate_arn" {
  description = "HTTPS 리스너에 사용할 ACM 인증서 ARN"
  type        = string
  default     = ""
}
