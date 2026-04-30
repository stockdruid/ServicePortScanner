# spscan Benchmark Harness — Stage 0

근거: [Service Port Scanner — 효율성 개선 연구 자료](../../docs/) §5.
모든 효율성 PR (Stage 1 이후) 은 변경 전/후 측정값을 본문에 첨부한다.

## 빌드

```bash
cmake -S . -B build -DSPSCAN_BUILD_BENCH=ON
cmake --build build --target spscan_bench --config Release
```

## 실행

```bash
# 모든 벤치
./build/tests/bench/spscan_bench

# 모듈별
./build/tests/bench/spscan_bench "[bench][rate_limiter]"
./build/tests/bench/spscan_bench "[bench][scanner]"
./build/tests/bench/spscan_bench "[bench][top_ports]"

# JSON 리포트 (PR 본문 첨부용)
./build/tests/bench/spscan_bench --reporter=json::out=bench-results.json

# CTest 통합
ctest --test-dir build -L bench --output-on-failure
```

## 측정 항목

| 모듈 | 항목 | 의미 |
|------|------|------|
| rate_limiter | acquire overhead | strand + atomic + token bucket refill 비용 |
| rate_limiter | adaptive convergence (10% loss) | 손실 환경에서 rate 감속 검증 |
| rate_limiter | adaptive convergence (clean) | 무손실 환경에서 rate 증속 검증 |
| rate_limiter | SRTT/RTTVAR 추적 | EWMA 동작 sanity |
| scanner | 단일 open port | loopback RTT 하한 |
| scanner | 50/200 open port 동시 | 동시성 효과 |
| scanner | closed port 지연 | OS RST/ICMP 응답 시간 |
| top_ports | 테이블 lookup | 무시 가능해야 |
| top_ports | top-100 vs 1-256 range | 포트 개수가 시간에 미치는 영향 |

## PR 첨부 규칙

각 효율성 PR 본문에 다음 표를 채워서 첨부한다.

| Bench | Before (mean) | After (mean) | Δ |
|-------|---------------|--------------|---|
| acquire 1000 @ 5000 pps |  ms |  ms |  % |
| 50 open ports concurrent |  ms |  ms |  % |
| 200 open ports concurrent |  ms |  ms |  % |
| top-100 scan |  ms |  ms |  % |

`spscan_bench --reporter=console` 출력의 `mean` 컬럼 값을 사용.

## 환경 표기

벤치 결과는 환경 의존이므로 PR 본문에 다음을 함께 적는다.

- OS / 커널 버전
- CPU 모델, 스레드 수
- Boost 버전
- 빌드 모드 (Release / RelWithDebInfo)
- 다른 부하 여부

## 알려진 한계

- **Loopback only**: 실제 네트워크 측정은 별도 통합 벤치 필요 (Stage 6 io_uring 전후).
- **Closed port 응답**: Windows 방화벽 설정에 따라 Closed 가 Filtered 로 떨어질 수 있음.
- **MockServer accept loop**: 단일 io_context, 단일 스레드. 동시 1000+ connect 폭주 시 backlog 한계.
