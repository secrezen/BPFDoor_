# BPFDoor 탐지 스크립트 모음

이 저장소는 BPFDoor 계열 백도어 흔적을 탐지하기 위한 두 가지 셸 스크립트를 제공합니다.

- `bpfdoor_checker.sh` : [SECREZEN] 2025년 작성된 강화형 점검 스크립트

모든 스크립트는 **루트 권한으로 실행**해야 하며, 실행 중 시스템 자원을 일시적으로 사용할 수 있습니다.

---

## 1. 공통 준비 사항

| 항목 | 설명 |
| --- | --- |
| 실행 권한 | `chmod +x bpfdoor_checker.sh bpftool` |
| 권장 환경 | Linux (systemd 기반 서버 권장) |
| 필수 권한 | root 혹은 passwordless sudo |
| 주의 | 가급적 단독 점검 시간에 실행하여 서비스 영향 최소화 |

> **참고:** `bpftool` 바이너리를 제공하고 있으나, 배포판에 포함된 최신 버전을 사용하는 것이 가장 안전합니다.

---

## 2. bpfdoor_checker.sh

### 실행 방법
```bash
# 루트 셸 또는 sudo -i 환경에서 실행
./bpfdoor_checker.sh
```

실행 시 `./bpfdoor_logs/` 디렉터리가 자동 생성되며, 여기서 로그와 중간 산출물을 관리합니다.

### 필수 도구
스크립트가 자동으로 존재 여부를 확인하며, 없을 경우 해당 검사만 건너뛰고 경고합니다.

| 도구 | 용도 |
| --- | --- |
| `bpftool` | BPF 프로그램/맵 조회 및 xlated/jited 덤프 |
| `ss` 또는 `netstat` | 네트워크/C2 스냅샷 |
| `sha256sum` | 파일 해시 비교 |
| `file` | 임시 경로 ELF 판별 |
| `lsof` | BPF 관련 핸들 점검 |
| `pgrep`, `ps`, `find` 등 | 프로세스 및 파일 검색 |

### 진단 범위
- **네트워크/C2**: `C2_INDICATORS` IP 배열과 `C2_PORTS` 포트를 기반으로 `ss`/`netstat` 출력에서 의심 연결 탐지
- **BPF 아티팩트**: `bpftool prog/map show`, `/sys/fs/bpf` 핀 객체 탐색, `name <unknown>` 프로그램의 xlated/jited 덤프 저장
- **악성 해시**: BPFDoor 관련 SHA256 목록과 시스템 주요 경로 대조
- **의심 이름·숨김 항목**: 프로세스 이름과 `/tmp`, `/var/tmp`, `/dev/shm`의 숨김 파일·디렉터리 점검
- **지속성 메커니즘**: cron, systemd unit, rc 스크립트, `/etc/ld.so.preload`, 프로세스 환경의 `LD_PRELOAD`
- **임시 경로 ELF**: `/tmp`, `/var/tmp`, `/dev/shm`, `/run` 경로에서 실행 가능한 ELF 파일 탐지
- **프로세스 마스커레이딩/숨김**: `/proc/<pid>/comm` vs cmdline 비교, `ps` 목록에 없는 PID 탐색

### 출력 파일
| 파일 | 설명 |
| --- | --- |
| `bpfdoor_logs/bpfdoor_scan_YYYYMMDD_HHMMSS.log` | 메인 로그 |
| `bpfdoor_logs/tmp_.../bpftool_prog_<id>_xlated.txt` | 의심 프로그램 xlated 덤프 |
| `bpfdoor_logs/tmp_.../bpftool_prog_<id>_jited.txt` | 의심 프로그램 jited 덤프 |
| `bpfdoor_logs/tmp_.../network_snapshot.txt` | 네트워크 스냅샷 (`ss` or `netstat`) |
| 기타 `tmp_.../*.txt` | cron/systemd/숨김 PID 등 중간 산출물 |

> 스캔 종료 후 `bpfdoor_logs/tmp_...` 디렉터리는 보존 또는 삭제 여부를 운영자의 정책에 따라 결정하십시오.

### 사용자 정의
- `C2_INDICATORS`, `C2_PORTS`, `MALWARE_HASHES`, `SUSPICIOUS_NAMES`, `BPF_NAME_HINTS` 배열은 최신 위협 인텔리전스에 맞추어 수시로 업데이트하십시오.
- 필요 시 `bpftool prog dump jited id ...` 명령을 주석 해제/추가하여 다른 옵션을 활용할 수 있습니다.

---

## 4. 공통 유의사항

- 스크립트는 **보조 진단 도구**입니다. 정상 소프트웨어와 충돌하거나 오탐(false positive)이 발생할 수 있으므로 결과를 반드시 수동으로 검토하세요.
- 탐지 범위는 공개된 BPFDoor 변종과 IOC에 기반하며, 새로운 변형은 탐지되지 않을 수 있습니다.
- 스크립트 실행 중 많은 파일을 검사하므로 시간과 I/O 부하가 발생할 수 있습니다. 시스템 상황을 고려해 실행하세요.
- 로그와 덤프 파일에는 민감 정보가 포함될 수 있으니 적절하게 보호 또는 파기하십시오.

---

## 5. FAQ

**Q1. 루트가 아닌 계정에서 실행하면 어떻게 되나요?**  
A. `bpfdoor_checker.sh`는 즉시 종료합니다.

**Q2. bpftool이 없는데 스크립트 실행이 가능한가요?**  
A. 가능합니다. 해당 기능만 건너뛰며 로그에 경고가 남습니다. 다만 정확한 BPF 진단을 위해 설치를 권장합니다.

**Q3. 네트워크 검사에 도메인 IOC를 넣고 싶습니다.**  
A. 현재는 IP/포트 기반으로 동작합니다. 도메인 감시가 필요하면 `C2_INDICATORS` 배열에 문자열을 추가하고 `grep` 조건을 확장하십시오.

---

## 6. 버전 정보

| 파일 | 버전/작성일 |
| --- | --- |
| `bpfdoor_checker.sh` | 2025-10 작성, 자체 버전 1.0 |

필요 시 버전 배너 또는 로그 상단에 날짜와 변경 사항을 직접 기입하시기 바랍니다.

---

## 7. 문의

- 스크립트 동작 중 예상치 못한 문제가 발생하면, 로그 전체와 함께 발생 시점을 기록하여 관리자에게 문의하십시오.
- 추가 기능 요청이나 IOC 업데이트는 별도의 이슈 트래커 또는 연락 창구를 통해 전달해 주세요.
