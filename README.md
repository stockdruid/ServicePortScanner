# Service Port Scanner

C++20 + Qt6 서비스 인식 포트 스캐너. 팀 프로젝트 (7인).

## 빌드 (예정)

```bash
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
cmake --build build
```

## 모듈 계획

| # | 모듈 | 경로 | 담당 |
|--|--|--|--|
| 1 | Core / Types | `src/core/` | TBD |
| 2 | Async Engine | `src/net/` | TBD |
| 3 | Scan Strategy | `src/scan/` | TBD |
| 4 | Service Detection | `src/detect/` | TBD |
| 5 | CVE Lookup | `src/cve/` | TBD |
| 6 | UI (Qt) | `src/ui/` | TBD |
| 7 | Orchestrator | `src/app/` | TBD |

## 브랜치 전략

- `main` — 팀 통합, 모듈 통합 PR만 머지
- `feat/<module>` — 각 팀원 모듈 작업 브랜치
