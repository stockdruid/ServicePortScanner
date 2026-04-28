# spscan — Ethics & Scope Policy

`spscan` 은 학습·연구·자기 자산 감사 목적의 서비스 인식 포트 스캐너이다.
본 문서는 도구를 안전하고 합법적으로 사용하기 위한 정책을 정의한다.

## 1. Allowed targets (기본 허용 범위)

별도 옵션 없이 스캔 가능한 대상:

- `127.0.0.0/8` — 로컬호스트
- `::1` — IPv6 로컬호스트
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — RFC1918 사설망
- `169.254.0.0/16`, `fe80::/10` — 링크 로컬
- ULA `fc00::/7`

## 2. External targets (외부 IP)

외부 IP 는 명시적 동의(`--i-know-what-im-doing`) 가 있을 때만 스캔 가능하다.
사용 전 다음을 확인할 책임이 사용자에게 있다.

- 대상 시스템 소유자에게 사전 서면 동의를 받았는가?
- 대상이 위치한 국가의 법률(예: 한국 정보통신망법 제48조)에 위반되지 않는가?
- 학교 네트워크/회사 네트워크의 AUP 에 부합하는가?

권한 없는 시스템에 대한 스캔은 형사 처벌 대상이 될 수 있다.

## 3. Rate limiting

기본 100 packets/sec. `--rate` 로 상향 가능하나 무제한 옵션은 제공하지 않는다.
DoS 가능성 있는 속도(>10000 pps) 사용 시 운영자가 모든 책임을 진다.

## 4. Audit log

모든 스캔은 향후 추가 예정인 `~/.spscan/audit.log` 에 timestamp, target,
모드, 사용자명을 append-only 로 기록한다.

## 5. No raw socket without privilege check

SYN 스캔 등 raw socket 모드는 OS 권한 확인 후에만 동작한다. 권한이 없으면
TCP connect 모드로 자동 fallback 된다.

## 6. Reporting bugs / abuse

- 본 도구로 발견한 취약점은 책임 있는 공개(Coordinated Disclosure) 원칙에
  따라 벤더에 먼저 보고한다.
- 본 도구가 악용되는 사례를 발견하면 프로젝트 issue 에 보고한다.

## 7. License & disclaimer

본 도구는 학교 과제 및 학습 목적이며, 사용으로 인해 발생하는 모든 결과의
책임은 사용자에게 있다.
