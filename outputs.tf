output "alb_dns_name" {
  description = "Application Load Balancer의 DNS 이름"
  value       = aws_lb.main.dns_name
}

output "alb_url" {
  description = "Application Load Balancer의 HTTP URL"
  value       = "http://${aws_lb.main.dns_name}"
}

output "web_server_private_ip" {
  description = "웹 서버 EC2 인스턴스의 프라이빗 IP 주소"
  value       = aws_instance.web.private_ip
}

output "web_server_public_ip" {
  description = "웹 서버 EC2 인스턴스의 퍼블릭 IP 주소"
  value       = aws_instance.web.public_ip
}

output "target_group_arn" {
  description = "타겟 그룹의 ARN"
  value       = aws_lb_target_group.web.arn
}

output "auth0_callback_url" {
  description = "Auth0 애플리케이션 설정에 입력할 Callback URL"
  value       = "https://${aws_lb.main.dns_name}/oauth2/idpresponse"
}

output "auth0_logout_url" {
  description = "Auth0 애플리케이션 설정에 입력할 Logout URL"
  value       = "https://${aws_lb.main.dns_name}/"
}

output "next_steps" {
  description = "배포 후 설정 단계"
  sensitive   = true
  value       = <<-EOT
  
  Terraform 배포가 성공적으로 완료되었습니다.
  
  다음 단계:
  
  1. Auth0 애플리케이션 설정:
     - Allowed Callback URLs: https://${aws_lb.main.dns_name}/oauth2/idpresponse
     - Allowed Logout URLs: https://${aws_lb.main.dns_name}/
     - Allowed Web Origins: https://${aws_lb.main.dns_name}
  
  2. ACM 인증서 발급 (HTTPS 필수):
     - AWS Certificate Manager를 통한 인증서 요청
     - 또는 개발 환경에서는 자체 서명 인증서 사용
  
  3. ALB HTTPS 리스너 설정:
     - 경로: EC2 Console > Load Balancers > Listeners
     - Port 443에 ACM 인증서와 함께 리스너 추가
     - 액션 설정: Authenticate (OIDC) > Forward to target group
     
  4. OIDC 인증 설정 정보:
     - Issuer: https://${var.auth0_domain}/
     - Authorization endpoint: https://${var.auth0_domain}/authorize
     - Token endpoint: https://${var.auth0_domain}/oauth/token
     - User info endpoint: https://${var.auth0_domain}/userinfo
     - Client ID: ${var.auth0_client_id}
     - Client Secret: (Auth0 대시보드에서 확인)
  
  5. 설정 검증:
     - HTTPS URL 접속 및 Auth0 로그인 리다이렉트 확인
     - 인증 플로우 정상 작동 확인
  
  리소스 관리:
  - 출력 확인: terraform output -raw next_steps
  - 리소스 삭제: terraform destroy
  
  참고: 테스트 완료 후 비용 최소화를 위해 즉시 리소스를 삭제하십시오.
  
  EOT
}
