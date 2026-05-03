# Service Port Scanner

[![CI](https://github.com/stockdruid/ServicePortScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/stockdruid/ServicePortScanner/actions/workflows/ci.yml)

C++20 + Qt6 서비스 인식 포트 스캐너. 팀 프로젝트 (7인).

## 빌드

CLI 만 (백엔드, 빠름):

```bash
cmake -B build -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

GUI 포함 (Qt6 첫 빌드 1~2시간):

```bash
cmake -B build_gui -S . -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-windows \
  -DVCPKG_MANIFEST_FEATURES=gui \
  -DSPSCAN_BUILD_GUI=ON
cmake --build build_gui --parallel
```

Windows 새 머신 셋업: [`docs/BUILD-WINDOWS.md`](docs/BUILD-WINDOWS.md) 참고.

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
