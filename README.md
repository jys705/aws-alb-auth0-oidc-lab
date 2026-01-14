# 🔐 ALB + Auth0 OIDC 연동 실습 프로젝트

## 📖 개요

이 프로젝트는 **AWS Application Load Balancer(ALB)**와 **Auth0**를 연동하여 **제로 트러스트 인증**을 구현하는 실습용 Terraform 코드입니다.

### 🎯 학습 목표

- ALB의 OIDC 인증 기능 이해
- Auth0 Regular Web Application 설정
- 제로 트러스트 아키텍처 구현
- 인프라 코드(IaC) 실습

### 💰 예상 비용

- **t2.micro EC2**: 프리티어 대상 (월 750시간 무료)
- **ALB**: 시간당 약 $0.0225 + 데이터 처리 비용
- **예상 실습 비용**: 2-3시간 실습 시 약 **500원 이하**

> ⚠️ **중요**: 실습 완료 후 즉시 `terraform destroy`로 리소스 삭제!

---

## 🏗️ 아키텍처

```
사용자
  ↓
[Route 53 / DNS]
  ↓
[Application Load Balancer]
  │
  ├─→ [Auth0 OIDC 인증]
  │     ↓
  │   ✅ 인증 성공
  │     ↓
  └─→ [EC2 웹 서버]
        (Private Subnet)
```

### 구성 요소

1. **ALB**: OIDC 인증 처리 + 트래픽 분산
2. **Auth0**: Identity Provider (IdP)
3. **EC2**: 간단한 웹 서버 (Apache httpd)
4. **보안 그룹**: 최소 권한 원칙 적용

---

## 🚀 실습 가이드

### 1단계: 사전 준비

#### 필수 요구사항

- AWS CLI 설치 및 설정
- Terraform v1.0 이상 설치
- Auth0 계정 (무료 계정 가능)
- (선택) ACM SSL 인증서 또는 자체 서명 인증서

#### AWS CLI 설정

```bash
aws configure
# AWS Access Key ID 입력
# AWS Secret Access Key 입력
# Default region: ap-northeast-2
```

---

### 2단계: Auth0 설정

#### 2.1 Auth0 Application 생성

1. [Auth0 Dashboard](https://manage.auth0.com/) 접속
2. **Applications** → **Create Application** 클릭
3. **이름 입력**: "ALB-OIDC-Lab"
4. **타입 선택**: **Regular Web Application** ✅
5. **Create** 클릭

#### 2.2 Auth0 설정 정보 확인

**Settings** 탭에서 다음 정보를 메모하세요:

- **Domain**: `dev-xxxxx.us.auth0.com`
- **Client ID**: `abc123...`
- **Client Secret**: `xyz789...` (절대 공개 금지!)

#### 2.3 Callback URL 설정 (나중에 입력)

Terraform apply 후 ALB DNS가 생성되면 다음을 입력:

```
Allowed Callback URLs:
https://<ALB-DNS>/oauth2/idpresponse

Allowed Logout URLs:
https://<ALB-DNS>/

Allowed Web Origins:
https://<ALB-DNS>
```

---

### 3단계: Terraform 배포

#### 3.1 저장소 클론 및 설정

```bash
cd ALB-sample

# 변수 파일 생성
cp terraform.tfvars.example terraform.tfvars

# terraform.tfvars 파일 편집
nano terraform.tfvars
```

#### 3.2 terraform.tfvars 파일 작성

```hcl
aws_region   = "ap-northeast-2"
project_name = "alb-auth0-lab"
instance_type = "t2.micro"

# Auth0 설정 (위에서 메모한 값 입력)
auth0_domain        = "dev-xxxxx.us.auth0.com"
auth0_client_id     = "your-client-id"
auth0_client_secret = "your-client-secret"
```

#### 3.3 Terraform 실행

```bash
# 초기화
terraform init

# 계획 확인
terraform plan

# 배포 (약 2-3분 소요)
terraform apply
```

#### 3.4 출력값 확인

```bash
terraform output

# 출력 예시:
# alb_dns_name = "alb-auth0-lab-xxxxx.ap-northeast-2.elb.amazonaws.com"
# auth0_callback_url = "https://alb-auth0-lab-xxxxx.ap-northeast-2.elb.amazonaws.com/oauth2/idpresponse"
```

---

### 4단계: Auth0 Callback URL 업데이트

1. Terraform 출력값에서 `auth0_callback_url` 복사
2. Auth0 Dashboard → Applications → 생성한 앱 → Settings
3. **Allowed Callback URLs**에 붙여넣기
4. **Save Changes**

---

### 5단계: ACM 인증서 발급 (HTTPS 필요)

#### 옵션 A: ACM 인증서 발급 (권장)

```bash
# AWS Console → Certificate Manager → Request certificate
# Domain: alb-auth0-lab.example.com (본인 도메인)
# Validation: DNS 또는 Email
```

#### 옵션 B: 자체 서명 인증서 (테스트용)

```bash
# 자체 서명 인증서 생성
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout selfsigned.key -out selfsigned.crt

# ACM에 Import (AWS Console 또는 CLI 사용)
```

---

### 6단계: ALB HTTPS 리스너 설정 (AWS Console)

Terraform에서는 HTTPS 리스너를 주석 처리해놨으므로, **AWS 콘솔에서 수동 설정**이 필요합니다.

#### 6.1 ALB 리스너 추가

1. AWS Console → **EC2** → **Load Balancers**
2. 생성된 ALB 선택 → **Listeners** 탭
3. **Add listener** 클릭

#### 6.2 HTTPS 리스너 설정

- **Protocol**: HTTPS
- **Port**: 443
- **Default SSL certificate**: ACM 인증서 선택

#### 6.3 OIDC 인증 규칙 추가

**Default actions**:

1. **Authenticate** (OIDC) 추가:
   - **Issuer**: `https://dev-xxxxx.us.auth0.com/` (끝에 `/` 필수!)
   - **Authorization endpoint**: `https://dev-xxxxx.us.auth0.com/authorize`
   - **Token endpoint**: `https://dev-xxxxx.us.auth0.com/oauth/token`
   - **User info endpoint**: `https://dev-xxxxx.us.auth0.com/userinfo`
   - **Client ID**: Auth0에서 복사
   - **Client Secret**: Auth0에서 복사

2. **Forward to** 추가:
   - **Target group**: Terraform이 생성한 타겟 그룹 선택

---

### 7단계: 테스트

#### 7.1 HTTP 접속 (인증 없음)

```bash
curl http://<ALB-DNS>
# "HTTPS Required" 메시지 확인
```

#### 7.2 HTTPS 접속 (Auth0 인증)

1. 브라우저에서 `https://<ALB-DNS>` 접속
2. Auth0 로그인 화면으로 리다이렉트 확인 ✅
3. 로그인 후 웹 페이지 표시 확인 ✅

#### 7.3 인증 흐름 확인

**브라우저 개발자 도구 (Network 탭)**에서 다음 흐름을 확인:

1. `https://<ALB-DNS>` → 302 Redirect
2. `https://dev-xxxxx.us.auth0.com/authorize` → Auth0 로그인
3. `https://<ALB-DNS>/oauth2/idpresponse` → 토큰 검증
4. `https://<ALB-DNS>` → 최종 페이지 표시

---

## 📸 실습 캡처 가이드 (블로그/보고서용)

### 필수 캡처 항목

1. **Auth0 Settings 화면**
   - Client ID, Domain이 보이는 화면
   - Callback URLs 설정 화면

2. **AWS ALB Listeners 화면**
   - HTTPS 리스너 규칙
   - Authenticate (OIDC) 액션 설정

3. **Auth0 로그인 화면**
   - ALB 접속 시 나타나는 Auth0 인증 페이지

4. **인증 성공 화면**
   - 최종적으로 표시되는 웹 페이지

5. **Terraform 출력값**
   - `terraform output` 결과 화면

---

## 🧹 실습 종료 및 리소스 삭제

### 리소스 삭제

```bash
# 모든 리소스 삭제 (약 1-2분 소요)
terraform destroy

# 확인 프롬프트에서 'yes' 입력
```

### 삭제 확인

```bash
# AWS Console에서 확인:
# - EC2 인스턴스 Terminated
# - ALB Deleted
# - 보안 그룹 Deleted
# - 타겟 그룹 Deleted
```

---

## 🔧 트러블슈팅

### 문제 1: "Certificate not found" 오류

**원인**: ACM 인증서가 없거나 다른 리전에 생성됨

**해결**:
- ALB와 동일한 리전(ap-northeast-2)에 ACM 인증서 생성
- 또는 자체 서명 인증서 사용

---

### 문제 2: Auth0 로그인 후 "Unable to complete" 오류

**원인**: Callback URL 설정 오류

**해결**:
1. Auth0 Dashboard → Settings 확인
2. Allowed Callback URLs: `https://<ALB-DNS>/oauth2/idpresponse` (정확히 일치해야 함)
3. 끝에 슬래시(`/`) 유무 확인

---

### 문제 3: "ERR_SSL_PROTOCOL_ERROR" 브라우저 오류

**원인**: HTTPS 리스너가 설정되지 않음

**해결**:
- AWS Console → ALB → Listeners에서 Port 443 리스너 확인
- SSL 인증서가 올바르게 연결되었는지 확인

---

### 문제 4: Target Group Unhealthy

**원인**: EC2 인스턴스의 웹 서버가 시작되지 않음

**해결**:
```bash
# EC2에 SSH 접속
ssh -i your-key.pem ec2-user@<EC2-PUBLIC-IP>

# Apache 상태 확인
sudo systemctl status httpd

# Apache 재시작
sudo systemctl restart httpd
```

---

## 📚 참고 자료

- [AWS ALB OIDC 인증 공식 문서](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html)
- [Auth0 OIDC 연동 가이드](https://auth0.com/docs/authenticate/protocols/openid-connect-protocol)
- [Terraform AWS Provider 문서](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

---

## 🛡️ 보안 권장사항

### 프로덕션 환경 적용 시

1. **Client Secret 관리**
   - AWS Secrets Manager 사용
   - Terraform에서 `data "aws_secretsmanager_secret"` 참조

2. **네트워크 격리**
   - EC2를 Private Subnet에 배치
   - NAT Gateway 사용

3. **로깅 및 모니터링**
   - ALB Access Logs 활성화 (S3)
   - CloudWatch 알람 설정

4. **IP 화이트리스트**
   - 필요 시 ALB 보안 그룹에 특정 IP만 허용

---

## 🎓 학습 포인트

### 이 실습을 통해 배운 것

✅ **ALB의 인증 레이어 분리**: 애플리케이션 코드 수정 없이 인프라 레벨에서 인증 구현

✅ **OIDC 표준 프로토콜**: Auth0 외에도 Okta, Google, Azure AD 등 다양한 IdP 연동 가능

✅ **제로 트러스트 아키텍처**: "모든 접근은 신뢰하지 않는다" 원칙 구현

✅ **IaC (Infrastructure as Code)**: Terraform을 통한 재현 가능한 인프라 구축

---

## 📝 라이선스

이 프로젝트는 교육 목적으로 자유롭게 사용 가능합니다.

---

## 🤝 기여

실습 중 발견한 문제나 개선사항은 Issue로 등록해 주세요!

---

**Happy Learning! 🚀**
