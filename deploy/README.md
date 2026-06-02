# Kubernetes 배포

Go API(server) + Next.js(web)를 단일 인그레스 뒤에 배포합니다. Kustomize 기반.

```
deploy/
  base/                 # 공통 매니페스트
    namespace.yaml
    server-deployment.yaml   # replicas=1, Recreate, PVC, non-root, RO rootfs, probes
    server-service.yaml      # ClusterIP :8080
    server-pvc.yaml          # SQLite 영속 (RWO)
    web-deployment.yaml      # Next standalone, non-root, probes
    web-service.yaml         # ClusterIP :3000
    ingress.yaml             # /api·/healthz → server, / → web (단일 호스트)
    kustomization.yaml
  overlays/
    local/              # OrbStack / kind / minikube
```

## 아키텍처 결정

- **단일 복제본 + PVC** — SQLite는 단일 파일 DB이고 스케줄러는 싱글톤이어야 합니다(복제본 N개 → 중복 Slack 푸시). `replicas: 1` + `strategy: Recreate`로 두 파드가 동시에 볼륨을 잡지 못하게 합니다.
- **단일 호스트 + path 분기** — 브라우저가 API를 직접 호출(`NEXT_PUBLIC_*`는 빌드 타임에 박힘)하므로, `/api`·`/healthz`는 server, 나머지는 web으로 같은 인그레스에서 라우팅합니다. web 이미지는 `NEXT_PUBLIC_API_BASE=""`로 빌드되어 `/api`를 **상대경로**(동일 출처)로 호출 → CORS/빌드타임 URL 문제 동시 해소.
- **보안 기본값** — non-root(서버 uid 65532 / 웹 1001), `readOnlyRootFilesystem`(server), `drop ALL` capabilities, `seccomp: RuntimeDefault`, resource requests/limits.

## 로컬 배포 (OrbStack / kind / minikube)

OrbStack은 Docker 이미지 스토어를 k8s와 공유하므로 **레지스트리 푸시 없이** 로컬 빌드 이미지를 바로 씁니다(base가 `imagePullPolicy: IfNotPresent` + `:local` 태그).

```bash
# 1) 이미지 빌드
docker build -f server/Dockerfile -t oss-digest-server:local server/
docker build -f web/Dockerfile    -t oss-digest-web:local    web/

# 2) 인그레스 컨트롤러 (없으면 1회 설치)
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.15.1/deploy/static/provider/cloud/deploy.yaml
kubectl wait -n ingress-nginx --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller --timeout=180s

# 3) 배포
kubectl apply -k deploy/overlays/local
kubectl wait -n oss-digest --for=condition=ready pod --all --timeout=120s

# 4) 접속 (인그레스 LoadBalancer IP)
IP=$(kubectl get svc -n ingress-nginx ingress-nginx-controller \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
curl "http://$IP/healthz"
curl "http://$IP/api/security?weeks=1"
open "http://$IP/"        # 대시보드
```

### 정리
```bash
kubectl delete -k deploy/overlays/local
```

## HTTPS (TLS) — `overlays/local-tls`

cert-manager로 self-signed 인증서를 발급해 HTTPS를 켭니다. 호스트는 `nip.io`라
DNS/hosts 설정이 필요 없습니다(`192-168-139-2.nip.io` → 인그레스 IP).

```bash
# 1) cert-manager 설치 (1회)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.20.2/cert-manager.yaml
kubectl wait --for=condition=Available -n cert-manager --timeout=180s \
  deploy/cert-manager deploy/cert-manager-webhook deploy/cert-manager-cainjector

# 2) TLS 오버레이 적용
kubectl apply -k deploy/overlays/local-tls
kubectl wait -n oss-digest --for=condition=Ready certificate/oss-digest-tls --timeout=90s

# 3) 접속 (self-signed → -k / 브라우저 경고 수락)
curl -k https://192-168-139-2.nip.io/healthz
open https://192-168-139-2.nip.io/
```

- HTTP는 자동으로 **308 → HTTPS** 리다이렉트됩니다(ingress-nginx ssl-redirect).
- 인그레스 IP가 다르면 `certificate.yaml`의 dnsNames와 `ingress-tls-patch.yaml`의 호스트를 그에 맞는 `<ip-dashed>.nip.io`로 바꾸세요.
- **인증서 키는 cert-manager가 생성**하므로 리포에 저장되지 않습니다.

### 프로덕션 TLS
`overlays/prod/`에서 self-signed `Issuer`를 **ACME(Let's Encrypt) `ClusterIssuer`**로,
호스트를 **실제 공개 도메인**으로 바꾸면 신뢰된 인증서가 자동 발급·갱신됩니다.
(공인 DNS가 인그레스로 향해야 하며, HTTP-01 또는 DNS-01 챌린지 필요)

## 프로덕션으로 갈 때 (overlay 추가)

`deploy/overlays/prod/`를 만들어 다음을 패치하세요.

- **이미지** — `:local` 대신 GHCR 태그(`ghcr.io/<owner>/openstack-security-digest/{server,web}:<ver>`). 태그 push 시 `release-images.yml`이 빌드·푸시합니다.
- **인그레스 host + TLS** — `host:` 지정 + cert-manager(`cluster-issuer`) 주석으로 TLS.
- **백업** — `server-data` PVC(설정·전송 이력 포함)를 정기 백업.
- **HA가 필요하면** — SQLite를 외부 DB(예: Postgres)로 교체하고 스케줄러에 리더 선출을 도입해야 다중 복제본이 가능합니다. (현재 구조는 단일 복제본 전제)

## 한국어 번역 (선택)

공지 본문을 한국어로 표시·푸시하려면 Claude API 키를 Secret으로 넣습니다(없으면 영문 그대로 동작).

```bash
kubectl -n oss-digest create secret generic oss-digest-secrets \
  --from-literal=anthropic-api-key=sk-ant-...
kubectl -n oss-digest rollout restart deploy/server
```

- 모델 기본값 `claude-haiku-4-5-20251001` (env `TRANSLATE_MODEL`로 변경 가능).
- 번역은 `translations` 테이블에 **콘텐츠 해시 기준으로 캐시**되어 재번역 비용이 없습니다.
- 신규 다이제스트는 스케줄러가 **사전 번역**하고 **Slack도 한국어**로 발송합니다.

## 운영 메모

- Slack webhook URL은 대시보드 **Settings**에서 입력 → PVC의 SQLite에 저장됩니다. 별도 Secret 불필요하지만, **PVC는 민감 데이터**(webhook + 이력)이므로 접근 통제 대상입니다.
- 스케줄러는 server 컨테이너 안에서 함께 돕니다(별도 CronJob 아님). 폴링 주기·임계치는 Settings에서 조정.
