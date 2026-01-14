# 🔐 ALB HTTPS 리스너 수동 설정 가이드

## 왜 수동 설정이 필요한가?

Terraform으로 HTTPS 리스너를 자동 생성하려면 **ACM 인증서 ARN**이 사전에 필요합니다. 
실습 환경에서는 도메인이 없거나 인증서 발급 전이므로, **Terraform으로 인프라를 먼저 생성**하고 
**AWS Console에서 HTTPS 리스너를 추가**하는 방식이 더 효율적입니다.

---

## 📋 단계별 가이드

### 1단계: Terraform으로 기본 인프라 생성

```bash
terraform init
terraform apply
```

**생성되는 리소스:**
- ALB (HTTP 리스너만 있음)
- EC2 웹 서버
- 보안 그룹
- 타겟 그룹

---

### 2단계: ACM 인증서 준비 (3가지 방법)

#### 방법 A: ACM에서 인증서 발급 (권장)

1. **AWS Console** → **Certificate Manager** (ACM)
2. **Request certificate** 클릭
3. **Public certificate** 선택
4. **도메인 이름 입력**: `alb-lab.example.com` (본인 소유 도메인)
5. **Validation method**: DNS 또는 Email 선택
6. **Request** 클릭
7. DNS/Email 검증 완료 후 **Issued** 상태 확인

#### 방법 B: 자체 서명 인증서 생성 (테스트용)

```bash
# OpenSSL로 자체 서명 인증서 생성
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout selfsigned.key \
  -out selfsigned.crt \
  -subj "/C=KR/ST=Seoul/L=Seoul/O=Lab/CN=alb-lab.local"

# Private key와 certificate를 ACM에 Import
aws acm import-certificate \
  --certificate fileb://selfsigned.crt \
  --private-key fileb://selfsigned.key \
  --region ap-northeast-2
```

#### 방법 C: Let's Encrypt 인증서 (수동 발급)

```bash
# Certbot 설치
sudo yum install -y certbot  # Amazon Linux
# 또는
brew install certbot  # macOS

# 인증서 발급 (수동 모드)
sudo certbot certonly --manual --preferred-challenges dns \
  -d alb-lab.example.com

# ACM에 Import
aws acm import-certificate \
  --certificate fileb:///etc/letsencrypt/live/alb-lab.example.com/cert.pem \
  --private-key fileb:///etc/letsencrypt/live/alb-lab.example.com/privkey.pem \
  --certificate-chain fileb:///etc/letsencrypt/live/alb-lab.example.com/chain.pem \
  --region ap-northeast-2
```

---

### 3단계: AWS Console에서 HTTPS 리스너 추가

#### 3.1 ALB 페이지 이동

1. **AWS Console** → **EC2** → **Load Balancers**
2. Terraform이 생성한 ALB 선택 (이름: `alb-auth0-lab-alb`)
3. **Listeners and rules** 탭 클릭

#### 3.2 HTTPS 리스너 추가

1. **Add listener** 버튼 클릭
2. 다음 정보 입력:

**Listener details:**
- **Protocol**: HTTPS
- **Port**: 443

**Secure listener settings:**
- **Default SSL/TLS certificate**: From ACM
- **Certificate**: 위에서 생성한 인증서 선택

#### 3.3 Default actions 설정

**Action 1: Authenticate (OIDC)**

**Add action** → **Authenticate** → **Authenticate with OIDC**

```
Issuer:
https://dev-xxxxx.us.auth0.com/

Authorization endpoint:
https://dev-xxxxx.us.auth0.com/authorize

Token endpoint:
https://dev-xxxxx.us.auth0.com/oauth/token

User info endpoint:
https://dev-xxxxx.us.auth0.com/userinfo

Client ID:
[Auth0에서 복사한 Client ID]

Client secret:
[Auth0에서 복사한 Client Secret]

Session cookie name: (기본값 사용)
AWSELBAuthSessionCookie

Session timeout: (기본값 사용)
604800 (7일)

Scope: (기본값 사용)
openid

On unauthenticated request: (기본값 사용)
authenticate
```

**⚠️ 중요 포인트:**
- **Issuer URL 끝에 슬래시(`/`) 필수!**
- Client Secret은 절대 공개되면 안 됩니다

**Action 2: Forward to target group**

**Add action** → **Forward to**

```
Target group:
[Terraform이 생성한 타겟 그룹 선택: alb-auth0-lab-tg]
```

#### 3.4 리스너 생성 완료

**Add** 버튼 클릭

---

### 4단계: Auth0 Callback URL 업데이트

1. **Terraform output에서 ALB DNS 확인:**

```bash
terraform output alb_dns_name
# 출력: alb-auth0-lab-xxxxx.ap-northeast-2.elb.amazonaws.com
```

2. **Auth0 Dashboard** → **Applications** → 생성한 앱 → **Settings**

3. **Application URIs 섹션에 입력:**

```
Allowed Callback URLs:
https://alb-auth0-lab-xxxxx.ap-northeast-2.elb.amazonaws.com/oauth2/idpresponse

Allowed Logout URLs:
https://alb-auth0-lab-xxxxx.ap-northeast-2.elb.amazonaws.com/

Allowed Web Origins:
https://alb-auth0-lab-xxxxx.ap-northeast-2.elb.amazonaws.com
```

4. **Save Changes** 클릭

---

### 5단계: 테스트

#### 5.1 HTTPS 접속

브라우저에서 다음 URL 접속:

```
https://<ALB-DNS>
```

#### 5.2 예상되는 동작

1. **Auth0 로그인 화면**으로 자동 리다이렉트
2. **로그인 완료** 후 웹 페이지 표시
3. **"🎉 인증 성공!"** 메시지 확인

#### 5.3 인증 흐름 확인 (개발자 도구)

**Chrome/Firefox 개발자 도구** → **Network 탭**:

```
1. GET https://<ALB-DNS>
   → 302 Found (Redirect to Auth0)

2. GET https://dev-xxxxx.us.auth0.com/authorize?...
   → 200 OK (Auth0 로그인 페이지)

3. POST https://dev-xxxxx.us.auth0.com/usernamepassword/login
   → 200 OK (로그인 성공)

4. GET https://<ALB-DNS>/oauth2/idpresponse?code=...&state=...
   → 302 Found (토큰 검증 및 쿠키 설정)

5. GET https://<ALB-DNS>
   → 200 OK (최종 페이지)
```

---

## 🔍 HTTPS 리스너 설정 확인 방법

### AWS CLI로 확인

```bash
# ALB의 모든 리스너 조회
aws elbv2 describe-listeners \
  --load-balancer-arn $(terraform output -raw target_group_arn | sed 's|:targetgroup/.*|:loadbalancer/app/alb-auth0-lab-alb/.*|') \
  --region ap-northeast-2

# HTTPS 리스너(Port 443) 규칙 확인
aws elbv2 describe-rules \
  --listener-arn <HTTPS-LISTENER-ARN> \
  --region ap-northeast-2
```

### AWS Console에서 확인

1. **EC2** → **Load Balancers** → ALB 선택
2. **Listeners and rules** 탭
3. **HTTPS:443** 리스너 클릭
4. **View/edit rules** 확인:
   - ✅ Authenticate (OIDC)
   - ✅ Forward to target group

---

## 🛠️ 트러블슈팅

### 문제 1: "ERR_SSL_PROTOCOL_ERROR"

**원인**: HTTPS 리스너가 없거나 인증서 오류

**해결**:
```bash
# 리스너 확인
aws elbv2 describe-listeners \
  --load-balancer-arn <ALB-ARN> \
  --query 'Listeners[?Port==`443`]'

# 결과가 비어있으면 리스너가 없는 것
```

---

### 문제 2: "Unable to complete your request"

**원인**: Auth0 Callback URL 불일치

**해결**:
1. Auth0 Settings → Allowed Callback URLs 확인
2. **정확히 일치해야 함**: `https://<ALB-DNS>/oauth2/idpresponse`
3. 끝에 슬래시 유무 확인

---

### 문제 3: "Issuer URL is not valid"

**원인**: Issuer URL 형식 오류

**해결**:
- ❌ 틀린 예: `https://dev-xxxxx.us.auth0.com`
- ✅ 올바른 예: `https://dev-xxxxx.us.auth0.com/` (끝에 `/` 필수!)

---

### 문제 4: Certificate 선택 불가

**원인**: 인증서가 다른 리전에 생성됨

**해결**:
- ALB와 **동일한 리전**(ap-northeast-2)에 ACM 인증서 생성
- 또는 인증서를 해당 리전으로 Import

---

## 📸 캡처 체크리스트 (블로그/보고서용)

### 필수 캡처

1. ✅ **ACM 인증서 Issued 상태**
2. ✅ **ALB Listeners 탭 - HTTPS:443 리스너**
3. ✅ **HTTPS 리스너 Rules - Authenticate (OIDC) 설정**
4. ✅ **Auth0 Settings - Callback URLs 설정**
5. ✅ **Auth0 로그인 화면**
6. ✅ **인증 성공 후 웹 페이지**
7. ✅ **Chrome DevTools - Network 탭 (인증 흐름)**

---

## 🎯 Terraform으로 자동화하고 싶다면?

### main.tf에 HTTPS 리스너 추가

```hcl
# variables.tf에 추가
variable "acm_certificate_arn" {
  description = "ACM SSL 인증서 ARN"
  type        = string
}

# main.tf에 추가
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type = "authenticate-oidc"

    authenticate_oidc {
      authorization_endpoint = "https://${var.auth0_domain}/authorize"
      client_id              = var.auth0_client_id
      client_secret          = var.auth0_client_secret
      issuer                 = "https://${var.auth0_domain}/"
      token_endpoint         = "https://${var.auth0_domain}/oauth/token"
      user_info_endpoint     = "https://${var.auth0_domain}/userinfo"
      
      session_cookie_name = "AWSELBAuthSessionCookie"
      session_timeout     = 604800  # 7일
      scope               = "openid"
    }
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}
```

### terraform.tfvars에 추가

```hcl
acm_certificate_arn = "arn:aws:acm:ap-northeast-2:123456789012:certificate/xxxxx"
```

### 재배포

```bash
terraform apply
```

---

## 🎓 학습 포인트

### 이 가이드에서 배운 것

✅ **ALB HTTPS 리스너 구조 이해**
✅ **OIDC 인증 흐름 (Authorization Code Flow)**
✅ **ACM 인증서 관리**
✅ **Auth0 Regular Web Application 설정**
✅ **Terraform과 수동 설정의 장단점**

---

**수고하셨습니다! 🎉**
