#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
COMPANY_NAME="SECREZEN"
SCRIPT_VERSION="1.0.0"
LOG_DIR="${SCRIPT_DIR}/bpfdoor_logs"
LOG_FILE="${LOG_DIR}/SECREZEN_bpfdoor_scan_${RUN_ID}.log"
TMP_DIR=""

mkdir -p "${LOG_DIR}"

cleanup() {
    if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR}" ]]; then
        rm -rf "${TMP_DIR}"
    fi
}
trap cleanup EXIT

TMP_DIR="$(mktemp -d "${LOG_DIR}/tmp_${RUN_ID}_XXXXXX")"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

declare -A TOOL_STATUS=()
declare -A MALWARE_HASHES=(
    ["c7f693f7f85b01a8c0e561bd369845f40bff423b0743c7aa0f4c323d9133b5d4"]="hpasmmld"
    ["3f6f108db37d18519f47c5e4182e5e33cc795564f286ae770aa03372133d15c4"]="smartadm"
    ["95fd8a70c4b18a9a669fec6eb82dac0ba6a9236ac42a5ecde270330b66f51595"]="hald-addon-volume"
    ["aa779e83ff5271d3f2d270eaed16751a109eb722fca61465d86317e03bbf49e4"]="dbus-srv-bin.txt"
    ["925ec4e617adc81d6fcee60876f6b878e0313a11f25526179716a90c3b743173"]="dbus-srv"
    ["29564c19a15b06dd5be2a73d7543288f5b4e9e6668bbd5e48d3093fb6ddf1fdb"]="inode262394"
    ["be7d952d37812b7482c1d770433a499372fde7254981ce2e8e974a67f6a088b5"]="dbus-srv"
    ["027b1fed1b8213b86d8faebf51879ccc9b1afec7176e31354fbac695e8daf416"]="dbus-srv"
    ["a2ea82b3f5be30916c4a00a7759aa6ec1ae6ddadc4d82b3481640d8f6a325d59"]="dbus-srv"
    ["e04586672874685b019e9120fcd1509d68af6f9bc513e739575fc73edefd511d"]="File_in_Inode"
    ["adfdd11d69f4e971c87ca5b2073682d90118c0b3a3a9f5fbbda872ab1fb335c6"]="gm"
    ["7c39f3c3120e35b8ab89181f191f01e2556ca558475a2803cb1f02c05c830423"]="rad"
)

C2_INDICATORS=("165.232.174.130")
C2_PORTS=("1337" "55555")
SUSPICIOUS_NAMES=("bpfdoor" "bpfd" "hpasmmld" "smartadm" "hald-addon-volume" "dbus-srv" "gm" "rad" "inode262394" "kthreadd" "initd" "ld.so.preload")
BPF_NAME_HINTS=("bpfdoor" "magic_map" "socket_map" "sock_ops" "sk_msg" "sockopt")
HASH_SEARCH_PATHS=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin" "/lib" "/lib64" "/usr/lib" "/usr/lib64" "/etc" "/opt" "/tmp" "/var/tmp" "/dev/shm")
HIDDEN_SCAN_PATHS=("/tmp" "/var/tmp" "/dev/shm")
TEMP_EXEC_SCAN_PATHS=("/tmp" "/var/tmp" "/dev/shm" "/run")
SYSTEMD_DIRS=("/etc/systemd/system" "/usr/lib/systemd/system" "/run/systemd/system" "${HOME}/.config/systemd/user")
CRON_PATTERNS=("/etc/crontab" "/etc/cron.d" "/var/spool/cron" "/var/spool/cron/crontabs")
RC_PATTERNS=("/etc/rc.local" "/etc/init.d")
MISSING_TOOLS=()

log() {
    local level="$1"; shift
    local message="$*"
    local ts
    ts="$(date +'%F %T')"
    local color prefix
    case "$level" in
        INFO) color="${GREEN}"; prefix="INFO";;
        WARN) color="${YELLOW}"; prefix="WARN";;
        CRIT) color="${RED}"; prefix="CRITICAL";;
        SECT) color="${BLUE}"; prefix="======";;
        *) color="${NC}"; prefix="$level";;
    esac
    if [[ "$level" == "SECT" ]]; then
        echo -e "${color}[${ts}] ====== ${message} ======${NC}"
        printf "[%s] ====== %s ======\n" "$ts" "$message" >> "$LOG_FILE"
    else
        echo -e "${color}[${ts}] ${prefix}: ${message}${NC}"
        printf "[%s] %s: %s\n" "$ts" "$prefix" "$message" >> "$LOG_FILE"
    fi
}

log_section() { log SECT "$1"; }
print_banner() {
    log_section "${COMPANY_NAME} BPFDoor Scanner v${SCRIPT_VERSION}"
    log_info "${COMPANY_NAME} :: Version ${SCRIPT_VERSION}"
}

log_info() { log INFO "$*"; }
log_warn() { log WARN "$*"; }
log_crit() { log CRIT "$*"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_crit "Root privileges are required. Aborting."
        exit 1
    fi
}

ensure_tool() {
    local cmd="$1"
    local label="$2"
    local local_path="${SCRIPT_DIR}/${cmd}"

    if [[ -x "$local_path" ]]; then
        TOOL_STATUS["$cmd"]=1
        if [[ ":$PATH:" != *":${SCRIPT_DIR}:"* ]]; then
            PATH="${SCRIPT_DIR}:$PATH"
            export PATH
        fi
        log_info "Required tool available: ${cmd} (using script directory)"
        return
    fi

    if command -v "$cmd" >/dev/null 2>&1; then
        TOOL_STATUS["$cmd"]=1
        log_info "Required tool available: ${cmd} (found in PATH)"
    else
        TOOL_STATUS["$cmd"]=0
        MISSING_TOOLS+=("${label:-$cmd}")
        log_warn "Required tool missing: ${cmd} (e.g., ${label})"
    fi
}


list_regex_from_array() {
    local -n arr_ref=$1
    local regex=""
    local first=true
    for entry in "${arr_ref[@]}"; do
        [[ -z "$entry" ]] && continue
        entry=$(printf '%s\n' "$entry" | sed 's/[^^[:alnum:][:space:]-]/\\&/g')
        if $first; then
            regex="$entry"
            first=false
        else
            regex="${regex}|${entry}"
        fi
    done
    printf '%s' "$regex"
}

check_requirements() {
    log_section "Environment checks"
    ensure_tool "bpftool" "bpftool package"
    ensure_tool "ss" "iproute2"
    ensure_tool "netstat" "net-tools"
    ensure_tool "sha256sum" "coreutils"
    ensure_tool "file" "file package"
    ensure_tool "lsof" "lsof package"
    ensure_tool "pgrep" "procps"
    ensure_tool "ps" "procps"
    ensure_tool "find" "findutils"
    if (( ${#MISSING_TOOLS[@]} > 0 )); then
        log_warn "Some tools are missing; certain checks may be limited: ${MISSING_TOOLS[*]}"
    else
        log_info "All required tools confirmed."
    fi
}

check_c2_connections() {
    log_section "Network / C2 inspection"
    local snapshot="${TMP_DIR}/network_snapshot.txt"
    local tool_used=""
    if [[ ${TOOL_STATUS["ss"]:-0} -eq 1 ]]; then
        if ss -tunap > "$snapshot" 2>/dev/null; then
            tool_used="ss"
        fi
    fi
    if [[ -z "$tool_used" && ${TOOL_STATUS["netstat"]:-0} -eq 1 ]]; then
        if netstat -tunap > "$snapshot" 2>/dev/null; then
            tool_used="netstat"
        fi
    fi
    if [[ -z "$tool_used" ]]; then
        log_warn "Unable to capture output from 'ss' or 'netstat'."
        return
    fi
    log_info "Network snapshot (${tool_used}) saved to: ${snapshot}"

    local found=false
    for indicator in "${C2_INDICATORS[@]}"; do
        [[ -z "$indicator" ]] && continue
        local hit_file="${TMP_DIR}/c2_${indicator//[^A-Za-z0-9]/_}.txt"
        if grep -F "$indicator" "$snapshot" > "$hit_file" 2>/dev/null; then
            log_crit "Connection involving C2 indicator '${indicator}' detected."
            cat "$hit_file" >> "$LOG_FILE"
            found=true
        else
            rm -f "$hit_file"
        fi
    done

    for port in "${C2_PORTS[@]}"; do
        [[ -z "$port" ]] && continue
        local hit_file="${TMP_DIR}/port_${port}.txt"
        local regex="[:.]${port}([^0-9]|$)"
        if grep -E "$regex" "$snapshot" > "$hit_file" 2>/dev/null; then
            log_warn "Known BPFDoor port ${port} observed."
            cat "$hit_file" >> "$LOG_FILE"
            found=true
        else
            rm -f "$hit_file"
        fi
    done

    if ! $found; then
        log_info "No connections to known C2 indicators or ports were found."
    fi
}

check_bpf_artifacts() {
    log_section "BPF artifact inspection"
    if [[ ${TOOL_STATUS["bpftool"]:-0} -ne 1 ]]; then
        log_warn "bpftool not found; skipping BPF object inspection."
        return
    fi

    local prog_output="${TMP_DIR}/bpftool_prog.txt"
    local map_output="${TMP_DIR}/bpftool_map.txt"
    local pinned_output="${TMP_DIR}/pinned_bpf.txt"
    local name_regex
    name_regex=$(list_regex_from_array BPF_NAME_HINTS)

    if bpftool prog show > "$prog_output" 2>/dev/null; then
        if [[ -s "$prog_output" ]]; then
            log_info "Loaded BPF program list written to: ${prog_output}"
            if [[ -n "$name_regex" ]] && grep -qiE "$name_regex" "$prog_output"; then
                log_warn "Suspicious BPFDoor-related patterns found in BPF program names."
                grep -Ei "$name_regex" "$prog_output" >> "$LOG_FILE"
            fi
            mapfile -t unknown_ids < <(awk -F: '/name <unknown>/ {
                id=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", id);
                sub(/[^0-9].*/, "", id);
                if (id ~ /^[0-9]+$/) print id;
            }' "$prog_output")
            for prog_id in "${unknown_ids[@]}"; do
                [[ -z "$prog_id" ]] && continue
                local dump_xlated="${TMP_DIR}/bpftool_prog_${prog_id}_xlated.txt"
                local dump_jited="${TMP_DIR}/bpftool_prog_${prog_id}_jited.txt"
                if bpftool prog dump xlated id "$prog_id" > "$dump_xlated" 2>/dev/null; then
                    log_warn "Dumped xlated instructions for unnamed BPF program (id=${prog_id}): ${dump_xlated}."
                fi
                if bpftool prog dump jited id "$prog_id" > "$dump_jited" 2>/dev/null; then
                    log_warn "Dumped jited instructions for unnamed BPF program (id=${prog_id}): ${dump_jited}."
                fi
            done
        else
            log_info "No BPF programs are loaded."
        fi
    else
        log_warn "Failed to execute 'bpftool prog show'."
    fi

    if bpftool map show > "$map_output" 2>/dev/null; then
        if [[ -s "$map_output" ]]; then
            log_info "Loaded BPF map list written to: ${map_output}"
            if [[ -n "$name_regex" ]] && grep -qiE "$name_regex" "$map_output"; then
                log_warn "Suspicious BPFDoor-related patterns found in BPF map names."
                grep -Ei "$name_regex" "$map_output" >> "$LOG_FILE"
            fi
        else
            log_info "No BPF maps are loaded."
        fi
    else
        log_warn "Failed to execute 'bpftool map show'."
    fi

    if [[ -d "/sys/fs/bpf" ]]; then
        if find /sys/fs/bpf -mindepth 1 -maxdepth 4 -printf '%p %y %s\n' 2>/dev/null > "$pinned_output"; then
            if [[ -s "$pinned_output" ]]; then
                log_info "Pinned BPF objects listed at: ${pinned_output}"
                if [[ -n "$name_regex" ]] && grep -qiE "$name_regex" "$pinned_output"; then
                    log_warn "Pinned BPF objects with suspicious names detected under /sys/fs/bpf."
                    grep -Ei "$name_regex" "$pinned_output" >> "$LOG_FILE"
                fi
            else
                log_info "No pinned BPF objects under /sys/fs/bpf."
            fi
        else
            log_warn "Failed to enumerate /sys/fs/bpf contents."
        fi
    else
        log_info "/sys/fs/bpf directory does not exist."
    fi
}

check_file_hashes() {
    log_section "Known hash inspection"
    if [[ ${TOOL_STATUS["sha256sum"]:-0} -ne 1 ]]; then
        log_warn "'sha256sum' not available; skipping known-hash check."
        return
    fi
    local found=false
    for base_dir in "${HASH_SEARCH_PATHS[@]}"; do
        [[ -d "$base_dir" ]] || continue
        while IFS= read -r -d $'\0' file_path; do
            local current_hash
            current_hash=$(sha256sum "$file_path" 2>/dev/null | awk '{print $1}')
            [[ -z "$current_hash" ]] && continue
            if [[ -n "${MALWARE_HASHES[$current_hash]:-}" ]]; then
                log_crit "File matching known malicious hash detected (${MALWARE_HASHES[$current_hash]}): ${file_path}."
                printf "HASH HIT\t%s\t%s\n" "$file_path" "$current_hash" >> "$LOG_FILE"
                found=true
            fi
        done < <(find "$base_dir" -xdev -type f -print0 2>/dev/null)
    done
    if ! $found; then
        log_info "No files matched known malicious hashes."
    fi
}

check_suspicious_processes_and_files() {
    log_section "Suspicious process/file inspection"
    local name_regex
    name_regex=$(list_regex_from_array SUSPICIOUS_NAMES)
    local found=false

    if [[ -n "$name_regex" ]]; then
        if pgrep -f "$name_regex" >/dev/null 2>&1; then
            log_warn "Processes with suspicious names detected."
            pgrep -af "$name_regex" >> "$LOG_FILE"
            found=true
        fi
    fi

    local scan_targets=("/tmp" "/var/tmp" "/dev/shm" "/etc" "/opt" "/usr/local/bin" "/usr/local/sbin" "/usr/libexec")
    for root_path in "${scan_targets[@]}"; do
        [[ -d "$root_path" ]] || continue
        while IFS= read -r -d $'\0' hit; do
            log_warn "Item matching suspicious pattern found: ${hit}."
            printf "SUSPECT FILE\t%s\n" "$hit" >> "$LOG_FILE"
            found=true
        done < <(find "$root_path" -maxdepth 2 -regextype posix-extended -regex ".*/(${name_regex})" -print0 2>/dev/null)
    done

    for hidden_path in "${HIDDEN_SCAN_PATHS[@]}"; do
        [[ -d "$hidden_path" ]] || continue
        while IFS= read -r -d $'\0' hidden_entry; do
            [[ "$hidden_entry" =~ /\.\.$ ]] && continue
            log_warn "Hidden entry discovered: ${hidden_entry}."
            printf "HIDDEN ENTRY\t%s\n" "$hidden_entry" >> "$LOG_FILE"
            found=true
        done < <(find "$hidden_path" -maxdepth 1 -mindepth 1 -name ".*" -print0 2>/dev/null)
    done

    if ! $found; then
        log_info "No suspicious process or file names detected."
    fi
}

check_persistence() {
    log_section "Persistence mechanism inspection"
    local found=false
    local pattern_regex
    pattern_regex=$(list_regex_from_array SUSPICIOUS_NAMES)
    pattern_regex="${pattern_regex}|/tmp/|/var/tmp/|/dev/shm/|LD_PRELOAD|bpfdoor"

    for cron_root in "${CRON_PATTERNS[@]}"; do
        [[ -e "$cron_root" ]] || continue
        while IFS= read -r -d $'\0' cron_file; do
            log_info "Inspecting cron file: ${cron_file}."
            if grep -Eiq "$pattern_regex" "$cron_file" 2>/dev/null; then
                log_warn "Suspicious entry found in cron file: ${cron_file}."
                grep -Ein "$pattern_regex" "$cron_file" >> "$LOG_FILE"
                found=true
            fi
        done < <(find "$cron_root" -type f -print0 2>/dev/null)
    done

    for sysd_dir in "${SYSTEMD_DIRS[@]}"; do
        [[ -d "$sysd_dir" ]] || continue
        while IFS= read -r -d $'\0' service_file; do
            log_warn "Suspicious entry found in systemd service file: ${service_file}."
            grep -Ein "$pattern_regex" "$service_file" >> "$LOG_FILE"
            found=true
        done < <(grep -rilE "$pattern_regex" "$sysd_dir" 2>/dev/null | tr '\n' '\0')
    done

    for rc_root in "${RC_PATTERNS[@]}"; do
        [[ -e "$rc_root" ]] || continue
        while IFS= read -r -d $'\0' rc_file; do
            if grep -Eiq "$pattern_regex" "$rc_file" 2>/dev/null; then
                log_warn "Suspicious entry found in RC script: ${rc_file}."
                grep -Ein "$pattern_regex" "$rc_file" >> "$LOG_FILE"
                found=true
            fi
        done < <(find "$rc_root" -type f -print0 2>/dev/null)
    done

    if [[ -f "/etc/ld.so.preload" ]]; then
        if [[ -s "/etc/ld.so.preload" ]]; then
            log_warn "Content detected in /etc/ld.so.preload."
            printf "--- /etc/ld.so.preload ---\n" >> "$LOG_FILE"
            cat "/etc/ld.so.preload" >> "$LOG_FILE"
            printf "--- end ---\n" >> "$LOG_FILE"
            found=true
        else
            log_info "/etc/ld.so.preload is empty."
        fi
    fi

    if [[ -n "${LD_PRELOAD:-}" ]]; then
        log_warn "LD_PRELOAD is set in the current shell environment: ${LD_PRELOAD}."
        printf "CURRENT SHELL LD_PRELOAD\t%s\n" "$LD_PRELOAD" >> "$LOG_FILE"
        found=true
    fi

    while IFS= read -r env_file; do
        if tr '\0' '\n' < "$env_file" 2>/dev/null | grep -q '^LD_PRELOAD='; then
            log_warn "LD_PRELOAD detected in process environment: ${env_file}."
            tr '\0' '\n' < "$env_file" | grep '^LD_PRELOAD=' >> "$LOG_FILE"
            found=true
        fi
    done < <(find /proc -maxdepth 2 -path "/proc/*/environ" -print 2>/dev/null)

    if ! $found; then
        log_info "No issues detected in primary persistence mechanisms."
    fi
}

check_temp_execs() {
    log_section "Temporary path executable inspection"
    if [[ ${TOOL_STATUS["file"]:-0} -ne 1 ]]; then
        log_warn "'file' command not available; skipping temporary path ELF check."
        return
    fi
    local found=false
    for temp_root in "${TEMP_EXEC_SCAN_PATHS[@]}"; do
        [[ -d "$temp_root" ]] || continue
        while IFS= read -r -d $'\0' candidate; do
            local description
            description=$(file "$candidate" 2>/dev/null)
            if grep -q 'ELF' <<<"$description"; then
                log_warn "ELF executable discovered in temporary path: ${candidate}."
                printf "TEMP ELF\t%s\t%s\n" "$candidate" "$description" >> "$LOG_FILE"
                found=true
            fi
        done < <(find "$temp_root" -maxdepth 2 -type f -print0 2>/dev/null)
    done
    if ! $found; then
        log_info "No ELF executables found in temporary paths."
    fi
}

check_process_masquerading() {
    log_section "Process masquerading inspection"
    local result_file="${TMP_DIR}/masquerade.txt"
    : > "$result_file"
    for proc_dir in /proc/[0-9]*; do
        [[ -d "$proc_dir" ]] || continue
        local comm_file="${proc_dir}/comm"
        local cmd_file="${proc_dir}/cmdline"
        if [[ ! -r "$comm_file" || ! -r "$cmd_file" ]]; then
            continue
        fi
        local comm_val
        comm_val=$(cat "$comm_file" 2>/dev/null)
        local first_arg
        first_arg=$(tr '\0' '\n' < "$cmd_file" 2>/dev/null | head -n1)
        local base_arg
        base_arg=$(basename "${first_arg:-}" 2>/dev/null)
        [[ -z "$comm_val" || -z "$base_arg" ]] && continue
        if [[ "$comm_val" != "$base_arg" ]]; then
            case "$comm_val:$base_arg" in
                java:java|python*:python*|python*:python|bash:bash|sh:sh) continue ;;
            esac
            local full_cmd
            full_cmd=$(tr '\0' ' ' < "$cmd_file" 2>/dev/null | cut -c1-256)
            printf "PID=%s COMM=%s CMD=%s\n" "${proc_dir##*/}" "$comm_val" "$full_cmd" >> "$result_file"
        fi
    done
    if [[ -s "$result_file" ]]; then
        log_warn "Potential masquerading processes detected."
        cat "$result_file" >> "$LOG_FILE"
    else
        log_info "No potential masquerading processes found."
    fi
}

check_hidden_processes() {
    log_section "Hidden process inspection"
    local ps_pids proc_pids
    ps_pids=$(ps -e -o pid= --no-headers 2>/dev/null | sort -n | uniq)
    proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | sed 's#/proc/##' | sort -n | uniq)
    if [[ -z "$ps_pids" || -z "$proc_pids" ]]; then
        log_warn "Failed to retrieve PID lists from ps or /proc."
        return
    fi
    local diff_file="${TMP_DIR}/hidden_procs.txt"
    comm -13 <(printf "%s\n" "$ps_pids") <(printf "%s\n" "$proc_pids") > "$diff_file"
    if [[ -s "$diff_file" ]]; then
        while read -r pid; do
            [[ -z "$pid" ]] && continue
            local exe_path="/proc/${pid}/exe"
            local comm_path="/proc/${pid}/comm"
            local cmd_path="/proc/${pid}/cmdline"
            local comm_val exe_val cmd_val
            comm_val=$(cat "$comm_path" 2>/dev/null)
            exe_val=$(readlink -f "$exe_path" 2>/dev/null)
            cmd_val=$(tr '\0' ' ' < "$cmd_path" 2>/dev/null | cut -c1-256)
            log_warn "PID present in /proc but missing from ps: PID=${pid}, COMM=${comm_val:-N/A}, EXE=${exe_val:-N/A}, CMD=${cmd_val:-N/A}."
            printf "HIDDEN PID\t%s\t%s\t%s\t%s\n" "$pid" "${comm_val:-N/A}" "${exe_val:-N/A}" "${cmd_val:-N/A}" >> "$LOG_FILE"
        done < "$diff_file"
    else
        log_info "No indications of hidden processes."
    fi
}

main() {
    require_root
    print_banner
    log_section "BPFDoor detection scan started"
    log_info "Log file: ${LOG_FILE}"
    log_info "Temporary artifact directory: ${TMP_DIR}"
    check_requirements
    check_c2_connections
    check_bpf_artifacts
    check_file_hashes
    check_suspicious_processes_and_files
    check_persistence
    check_temp_execs
    check_process_masquerading
    check_hidden_processes
    log_section "BPFDoor detection scan completed"
    log_warn "This script is an auxiliary tool and may not detect every variant."
    log_info "Refer to ${LOG_FILE} and artifacts under ${TMP_DIR} for details."
}

main "$@"

