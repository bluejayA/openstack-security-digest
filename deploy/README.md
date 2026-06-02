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

## 프로덕션으로 갈 때 (overlay 추가)

`deploy/overlays/prod/`를 만들어 다음을 패치하세요.

- **이미지** — `:local` 대신 GHCR 태그(`ghcr.io/<owner>/openstack-security-digest/{server,web}:<ver>`). 태그 push 시 `release-images.yml`이 빌드·푸시합니다.
- **인그레스 host + TLS** — `host:` 지정 + cert-manager(`cluster-issuer`) 주석으로 TLS.
- **백업** — `server-data` PVC(설정·전송 이력 포함)를 정기 백업.
- **HA가 필요하면** — SQLite를 외부 DB(예: Postgres)로 교체하고 스케줄러에 리더 선출을 도입해야 다중 복제본이 가능합니다. (현재 구조는 단일 복제본 전제)

## 운영 메모

- Slack webhook URL은 대시보드 **Settings**에서 입력 → PVC의 SQLite에 저장됩니다. 별도 Secret 불필요하지만, **PVC는 민감 데이터**(webhook + 이력)이므로 접근 통제 대상입니다.
- 스케줄러는 server 컨테이너 안에서 함께 돕니다(별도 CronJob 아님). 폴링 주기·임계치는 Settings에서 조정.
