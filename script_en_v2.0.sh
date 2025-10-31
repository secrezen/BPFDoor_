#!/bin/bash

#Comments are written to make it easier for users to check the code during deployment.
############Features###########
#[1] YARA Rule Scan // Note : Disabled by default // Remove comments if necessary. Remove the # comment before setup_and run_yara_scan in the main() function. (Yara must be installed.)
#[2] File Hash Check
#[3] Suspicious Process and File Name/Path Check
#[4] Network Scan
#[5] BPF Related Artifact Check
#[6] Persistence Check
#[7] Process Masquerading Check
#[8] Suspicious ELF File Check in Temporary Paths
#[9] Recently Modified Executable File Check
#[10] Hidden Process Check


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$SCRIPT_DIR:$PATH"

LOG_FILE="PIOLINK_scan_$(date +%Y%m%d_%H%M%S).log"
C2_IP="165.232.174.130"

RED='\033[0;31m'
YELLOW='\033[1;33m' 
NC='\033[0m' #default
BLUE='\033[0;34m'
GREEN='\033[0;32m' 

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

SUSPICIOUS_NAMES_PATHS=(
    "hpasmmld"
    "smartadm"
    "hald-addon-volume"
    "dbus-srv"
    "gm"
    "rad"
    # "." is for checking hidden files
    "/dev/shm/."
    "/tmp/."
    "kthreadd"
    "initd"
)

YARA_RULE_FILE="./bpfdoor_pattern.yar"

#Required program installation status (1 if not installed (default)/0 if installed) // Most are typically pre-installed, but YARA might not be ?!?!
YARA_INSTALLED=1
BPFTOOL_INSTALLED=1
SS_INSTALLED=1
NETSTAT_INSTALLED=1
LSOF_INSTALLED=1
FILE_CMD_INSTALLED=1
SHA256SUM_INSTALLED=1

gen_log() {
    local message_body="$1"
    local timestamp_prefix="[$(date +'%Y-%m-%d %H:%M:%S')]"
    local terminal_output="$message_body"
    local log_output="$message_body"

    if [[ "$message_body" == WARN:* ]]; then
        terminal_output="${RED}WARN:${NC}${message_body#WARN:}"
        log_output="WARN:${message_body#WARN:}"
    elif [[ "$message_body" == CRITICAL:* ]]; then
        terminal_output="${YELLOW}CRITICAL:${NC}${message_body#CRITICAL:}"
        log_output="CRITICAL:${message_body#CRITICAL:}"
    elif [[ "$message_body" == INFO:* ]]; then
        terminal_output="${GREEN}INFO:${NC}${message_body#INFO:}"
        log_output="INFO:${message_body#INFO:}"
    else
        log_output=$(echo "$message_body" | sed 's/\x1b\[[0-9;]*m//g')
    fi
    echo -e "${timestamp_prefix} ${terminal_output}"
    echo "${timestamp_prefix} ${log_output}" >> "$LOG_FILE"
}

progress_bar() {
    local current=$1 total=$2 width=40 filled empty
    filled=$(( current * width / total ))
    empty=$(( width - filled ))
    printf "\r["
    printf "%0.s#" $(seq 1 $filled)
    printf "%0.s-" $(seq 1 $empty)
    printf "] %d/%d" "$current" "$total"
}

check_command_exists() {
    local cmd_name=$1
    local package_name=$2
    if command -v "$cmd_name" &> /dev/null; then
        gen_log "INFO: Required program '$cmd_name' is installed."
        return 0
    else
        gen_log "WARN: Required program '$cmd_name' is not installed (e.g., sudo apt install $package_name or yum install $package_name). Some checks may be skipped."
        return 1
    fi
}

display_banner_and_init() {
    gen_log "${BLUE}========== BPFDoor Malware Scan Script ==========${NC}"
    gen_log "${BLUE}     ____ ___ ___  _     ___ _   _ _  __  ${NC}"
    gen_log "${BLUE}    |  _ \_ _/ _ \| |   |_ _| \ | | |/ /  ${NC}"
    gen_log "${BLUE}    | |_) | | | | | |    | ||  \| | ' /   ${NC}"
    gen_log "${BLUE}    |  __/| | |_| | |___ | || |\  | . \   ${NC}"
    gen_log "${BLUE}    |_|  |___\___/|_____|___|_| \_|_|\_\  ${NC}"
    gen_log "${BLUE}              version: 25.5v1             ${NC}"
    gen_log "${BLUE}===================================================${NC}"
    gen_log "Log File: $LOG_FILE"
    gen_log "Temporary Directory: . (Manual deletion recommended after script execution)"
    echo "" >> "$LOG_FILE"

    if [[ $EUID -ne 0 ]]; then
        gen_log "WARN: Script is not running with root privileges. Some scan functions may be limited."
    fi
    echo "" >> "$LOG_FILE"

    gen_log "INFO: Checking for required programs..."
    check_command_exists "sha256sum" "coreutils"; SHA256SUM_INSTALLED=$?
    check_command_exists "yara" "yara"; YARA_INSTALLED=$?
    check_command_exists "bpftool" "linux-tools-common (Debian/Ubuntu) or bpftool (RHEL/CentOS)"; BPFTOOL_INSTALLED=$?
    check_command_exists "ss" "iproute2"; SS_INSTALLED=$?
    check_command_exists "netstat" "net-tools"; NETSTAT_INSTALLED=$?
    check_command_exists "lsof" "lsof"; LSOF_INSTALLED=$?
    check_command_exists "file" "file"; FILE_CMD_INSTALLED=$?
    
    gen_log "INFO: Program check complete. If any programs are not installed, related functions may operate with limitations or be skipped."
    echo "" >> "$LOG_FILE"
}

#YARA Rule Definition
setup_and_run_yara_scan() {
    if [ "$YARA_INSTALLED" -ne 0 ]; then
        gen_log "WARN: YARA is not installed, skipping YARA scan."
        return
    fi

    gen_log "INFO: [YARA] Generating YARA rules..."
    cat <<EOF > "$YARA_RULE_FILE"
rule BPFDoor_Linux_Pattern {
    meta:
        description = "Detect BPFDoor malware and related artifacts on Linux"
        author = "PIOLINK"
        date = "$(date +%Y-%m-%d)"
    strings:
        //ELF magic number
        \$elf_magic = { 7f 45 4c 46 } at 0
        //Strings frequently used or detected in BPFDoor
        \$str_bin_sh = "/bin/sh" ascii wide
        \$str_setsockopt = "setsockopt" ascii wide nocase
        \$str_socket = "socket" ascii wide nocase
        //bpf system call related function names, etc.
        \$str_bpf_syscall = "bpf" ascii wide
        //Attempt to change process name
        \$str_prctl = "prctl" ascii wide
        //LD_PRELOAD environment variable string
        \$str_ld_preload_env = "LD_PRELOAD" ascii
        //BPF socket options
        \$str_so_attach_bpf = "SO_ATTACH_BPF" ascii
        \$str_so_detach_bpf = "SO_DETACH_BPF" ascii
        //BPFDoor specific strings
        \$bpfdoor_str1 = "BPFDoor" ascii nocase
        //Related to kernel symbol access
        \$bpfdoor_str2 = "get_kernel_syms" ascii
        //Frequently used in BPF
        \$bpfdoor_str3 = "bpf_probe_read" ascii

    condition:
        \$elf_magic and filesize < 3MB and (
            (2 of (\$str_bin_sh, \$str_setsockopt, \$str_socket, \$str_bpf_syscall, \$str_so_attach_bpf)) or
            (\$str_prctl and \$str_bin_sh) or
            (1 of (\$bpfdoor_str1, \$bpfdoor_str2, \$bpfdoor_str3))
    )
}

rule LD_PRELOAD_Hijack_Pattern {
    meta:
        description = "Detect LD_PRELOAD hijacking"
        author = "PIOLINK"
        date = "$(date +%Y-%m-%d)"
    strings:
        \$elf_magic = { 7f 45 4c 46 } at 0
        \$str_bin_sh = "/bin/sh" ascii
        \$str_socket_call = "socket(" ascii
        \$str_connect_call = "connect(" ascii
        \$str_dup2_call = "dup2(" ascii
        \$str_execve_call = "execve(" ascii
        \$str_system_call = "system(" ascii
    condition:
        \$elf_magic and (
            (1 of (\$str_socket_call, \$str_connect_call, \$str_system_call)) and (\$str_bin_sh or \$str_execve_call or \$str_dup2_call)
        ) and filesize < 1MB
}
EOF
    gen_log "INFO: [YARA] YARA rules have been generated in '$YARA_RULE_FILE'."

    gen_log "INFO: [YARA] Collecting executable files (ELF) in the system. (This may take some time)"
    local TARGET_FILES_LIST="./elf_targets_for_yara.txt"
    #Search paths
    local SEARCH_PATHS_YARA=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin" "/lib" "/lib64" "/usr/lib" "/usr/lib64" "/opt" "/tmp" "/var/tmp" "/dev/shm" "/run" "$HOME" "/etc" "/usr/libexec")
    
    echo "" > "$TARGET_FILES_LIST"
    local idx=0 total_paths=${#SEARCH_PATHS_YARA[@]}
    for path_to_scan in "${SEARCH_PATHS_YARA[@]}"; do
        ((idx++))
        progress_bar "$idx" "$total_paths"
        if [ -d "$path_to_scan" ]; then
            #Only ELF type files with execute permission (some files may not be accessible without permission)
            find "$path_to_scan" -type f -perm /111 -print0 2>/dev/null | xargs -0 -r file -N 2>/dev/null | grep ': ELF' | awk -F: '{print $1}' >> "$TARGET_FILES_LIST"
        fi
    done
    printf "\n"
    sort -u "$TARGET_FILES_LIST" -o "$TARGET_FILES_LIST"
    local TARGET_COUNT=$(wc -l < "$TARGET_FILES_LIST")
    gen_log "INFO: [YARA] Collected a total of $TARGET_COUNT ELF files for analysis."

    if [ "$TARGET_COUNT" -eq 0 ]; then
        gen_log "WARN: [YARA] No ELF files found for analysis. Check paths and permissions."
        return
    fi

    gen_log "INFO: [YARA] Starting YARA scan..."
    local yara_output_file="./yara_scan_results.txt"
    
    if [ -s "$TARGET_FILES_LIST" ]; then 
        xargs -a "$TARGET_FILES_LIST" -I {} yara "$YARA_RULE_FILE" "{}" >> "$yara_output_file" 2>/dev/null
    fi

    if [ -s "$yara_output_file" ]; then
        gen_log "CRITICAL: [YARA] YARA detection results:"
        cat "$yara_output_file" | tee -a "$LOG_FILE"
    else
        gen_log "INFO: [YARA] No items detected in YARA scan."
    fi
    echo "" >> "$LOG_FILE"
}

check_files_by_hash() {
    if [ "$SHA256SUM_INSTALLED" -ne 0 ]; then
        gen_log "WARN: sha256sum is not installed, skipping file hash check.(This may take some time)"
        return
    fi

    gen_log "INFO: [File Hash] Starting known malicious file hash check..."
    local found_suspicious_file_hash=false
    local SEARCH_PATHS_HASH=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/lib" "/usr/lib" "/etc" "/tmp" "/var/tmp" "/dev/shm" "/opt" "/home" "/run" "/usr/local/bin" "/usr/local/sbin" "/usr/libexec")
    local total_hash_paths=${#SEARCH_PATHS_HASH[@]} idx_hash=0

    for search_dir in "${SEARCH_PATHS_HASH[@]}"; do
        ((idx_hash++))
        progress_bar "$idx_hash" "$total_hash_paths"
        if [ ! -d "$search_dir" ]; then
            gen_log "WARN(Search Path): [File Hash] Directory '$search_dir' not found."
            continue
        fi

        find "$search_dir" -type f -print0 2>/dev/null | while IFS= read -r -d $'\0' file_path; do
            [ ! -r "$file_path" ] && continue
            current_sha256=$(sha256sum "$file_path" 2>/dev/null | awk '{print $1}')
            [ -z "$current_sha256" ] && continue 

            for known_hash_val in "${!MALWARE_HASHES[@]}"; do
                if [[ "$current_sha256" == "$known_hash_val" ]]; then
                    gen_log "  CRITICAL: [File Hash] Found a file matching a known malicious file hash!"
                    gen_log "  Suspected Malware Name: ${MALWARE_HASHES[$known_hash_val]}"
                    gen_log "  File Path: $file_path"
                    gen_log "  SHA256: $current_sha256"
                    found_suspicious_file_hash=true
                fi
            done
        done
    done
    printf "\n"

    if [ "$found_suspicious_file_hash" = false ]; then
        gen_log "INFO: [File Hash] No files matching known malicious file hashes were found."
    fi
    echo "" >> "$LOG_FILE"
}

check_suspicious_processes_and_files() {
    gen_log "INFO: [Suspicious Names] Starting suspicious process and file name/path pattern check..."
    local found_suspicious_item_name=false
    for pattern in "${SUSPICIOUS_NAMES_PATHS[@]}"; do
        if pgrep -fli "$pattern" &>/dev/null; then
            gen_log "WARN: [Suspicious Names] Found a process containing the suspicious pattern '$pattern'."
            pgrep -fli "$pattern" | while read -r line; do gen_log "  Process Info: $line"; done
            found_suspicious_item_name=true
        fi

        local LIMITED_SEARCH_PATHS_NAMES=("/tmp" "/var/tmp" "/dev/shm" "/etc" "/run" "/usr/local/bin" "/usr/local/sbin" "/usr/bin" "/usr/sbin" "/opt")
        for s_path in "${LIMITED_SEARCH_PATHS_NAMES[@]}"; do
            [ ! -d "$s_path" ] && continue

            find "$s_path" -name "$pattern" -print0 2>/dev/null | while IFS= read -r -d $'\0' found_file; do
                gen_log "WARN: [Suspicious Names] Found an item matching the suspicious file/directory pattern '$pattern': $found_file"
                found_suspicious_item_name=true
            done
            #Hidden file check
            if [[ "$pattern" == */.* ]]; then
                :
            elif [[ "$pattern" == "." ]]; then 
                find "$s_path" -maxdepth 1 -name ".*" -type d -print0 2>/dev/null | while IFS= read -r -d $'\0' found_dir; do
                    if [[ "$found_dir" == "$s_path/."* ]]; then
                        gen_log "WARN: [Suspicious Names] Found a suspicious hidden directory pattern (starting with '.') in '$s_path': $found_dir"
                        found_suspicious_item_name=true
                    fi
                done
                find "$s_path" -maxdepth 1 -name ".*" -type f -print0 2>/dev/null | while IFS= read -r -d $'\0' found_h_file; do
                    if [[ "$found_h_file" == "$s_path/."* ]]; then
                        gen_log "WARN: [Suspicious Names] Found a suspicious hidden file pattern (starting with '.') in '$s_path': $found_h_file"
                        found_suspicious_item_name=true
                    fi
                done
            else 
                #Check .prefix for general patterns
                find "$s_path" -name ".$pattern" -print0 2>/dev/null | while IFS= read -r -d $'\0' found_hidden_file; do
                    gen_log "WARN: [Suspicious Names] Found a suspicious hidden file/directory pattern (.$pattern): $found_hidden_file"
                    found_suspicious_item_name=true
                done
            fi
        done
    done

    if [ "$found_suspicious_item_name" = false ]; then
        gen_log "INFO: [Suspicious Names] No suspicious process or file name/path patterns found."
    fi
    echo "" >> "$LOG_FILE"
}

check_network_connections() {
    gen_log "INFO: [Network] Starting network connection check..."
    local found_c2_connection=false
    local network_tool_used=""

    #C2 IP check (using ss and netstat)
    if [ "$SS_INSTALLED" -eq 0 ]; then
        network_tool_used="ss"
        if ss -ntp | grep -q "$C2_IP"; then
            gen_log "CRITICAL: [Network] Detected suspicious network connection (TCP) to known C2 IP ($C2_IP) using 'ss'."
            ss -ntp | grep "$C2_IP" | while read -r line; do gen_log "  Connection Info: $line"; done
            found_c2_connection=true
        fi
        if ss -nup | grep -q "$C2_IP"; then
            gen_log "CRITICAL: [Network] Detected suspicious network connection (UDP) to known C2 IP ($C2_IP) using 'ss'."
            ss -nup | grep "$C2_IP" | while read -r line; do gen_log "  Connection Info: $line"; done
            found_c2_connection=true
        fi
    elif [ "$NETSTAT_INSTALLED" -eq 0 ]; then
        network_tool_used="netstat"
        if netstat -ntp | grep -q "$C2_IP"; then
            gen_log "CRITICAL: [Network] Detected suspicious network connection (TCP) to known C2 IP ($C2_IP) using 'netstat'."
            netstat -ntp | grep "$C2_IP" | while read -r line; do gen_log "  Connection Info: $line"; done
            found_c2_connection=true
        fi
        if netstat -nup | grep -q "$C2_IP"; then
            gen_log "CRITICAL: [Network] Detected suspicious network connection (UDP) to known C2 IP ($C2_IP) using 'netstat'."
            netstat -nup | grep "$C2_IP" | while read -r line; do gen_log "  Connection Info: $line"; done
            found_c2_connection=true
        fi
    else
        gen_log "WARN: [Network] 'ss' or 'netstat' command not found, skipping C2 IP connection check."
    fi

    if [ "$found_c2_connection" = false ] && [ -n "$network_tool_used" ]; then
        gen_log "INFO: [Network] No active connection to known C2 IP ($C2_IP) found (used $network_tool_used)."
    fi

    #BPF related listening port and connection check
    ####
    if [ "$SS_INSTALLED" -eq 0 ]; then
        gen_log "INFO: [Network] Using 'ss' to check for BPF-related suspicious network connections/listening. (False positives possible // Review needed)"
        local ss_bpf_output="./ss_bpf_results.txt"
        sudo ss -tunap | grep -iE 'bpf|users:\(\("bpfdoor",pid=[0-9]+,fd=[0-9]+\)\)|:1337|:55555'
        sudo ss -tunap 2>/dev/null | awk '$NF ~ /bpf/ || $0 ~ /bpfopt/ {print}' > "$ss_bpf_output"
    ####
        if [ -s "$ss_bpf_output" ]; then
            gen_log "WARN: [Network] BPF-related suspicious network connections/listening identified by 'ss' command. (Manual review needed):"
            sort -u "$ss_bpf_output" | tee -a "$LOG_FILE"
        else
            gen_log "INFO: [Network] No BPF-related suspicious network connections/listening found using 'ss' command."
        fi
    else
        gen_log "WARN: [Network] 'ss' command not available, skipping BPF-related network connection check."
    fi
    echo "" >> "$LOG_FILE"
}

check_bpf_artifacts() {
    gen_log "INFO: [BPF] Starting BPF related artifact check..."

    #Using bpftool
    if [ "$BPFTOOL_INSTALLED" -eq 0 ]; then
        gen_log "INFO: [BPF] Using 'bpftool' to check loaded BPF programs and maps."
        local bpftool_prog_output="./bpftool_prog.txt"
        local bpftool_map_output="./bpftool_map.txt"
        
        if sudo bpftool prog show > "$bpftool_prog_output" 2>/dev/null; then
            if [ -s "$bpftool_prog_output" ]; then
                gen_log "INFO: [BPF] List of loaded BPF programs (bpftool prog show):"
                cat "$bpftool_prog_output" | tee -a "$LOG_FILE"
                if grep -q "name <unknown>" "$bpftool_prog_output"; then
                    gen_log "WARN: [BPF] Unnamed (name <unknown>) BPF program is loaded. Review for BPFDoor possibility."
                fi
            else
                gen_log "INFO: [BPF] No BPF programs loaded (bpftool prog show)."
            fi
        else
            gen_log "WARN: [BPF] Error executing 'bpftool prog show' (root privileges may be required)."
        fi

        if sudo bpftool map show > "$bpftool_map_output" 2>/dev/null; then
            if [ -s "$bpftool_map_output" ]; then
                gen_log "INFO: [BPF] List of loaded BPF maps (bpftool map show):"
                cat "$bpftool_map_output" | tee -a "$LOG_FILE"
                
                if grep -qiE "bpfdoor_map|magic_map|socket_map" "$bpftool_map_output"; then
                    gen_log "WARN: [BPF] BPF map with a suspicious name related to BPFDoor found (Manual review needed)!"
                fi
            else
                gen_log "INFO: [BPF] No BPF maps loaded (bpftool map show)."
            fi
        else
            gen_log "WARN: [BPF] Error executing 'bpftool map show' (root privileges may be required)."
        fi
    else
        gen_log "WARN: [BPF] 'bpftool' is not installed, skipping detailed BPF object check."
    fi

    #Check processes using BPF related files/sockets
    if [ "$LSOF_INSTALLED" -eq 0 ]; then
        gen_log "INFO: [BPF] Using 'lsof' to check processes using BPF related files/sockets (False positives possible, review needed)."
        local lsof_bpf_output="./lsof_bpf_results.txt"

        sudo lsof 2>/dev/null | grep -i 'bpf' > "$lsof_bpf_output"
        if [ -s "$lsof_bpf_output" ]; then
            gen_log "WARN: [BPF] Processes suspected of BPF-related use via 'lsof' (Manual review needed):"
            cat "$lsof_bpf_output" | tee -a "$LOG_FILE"
        else
            gen_log "INFO: [BPF] No processes found using BPF-related files via 'lsof'."
        fi
    else
        gen_log "WARN: [BPF] 'lsof' is not installed, skipping BPF file/socket usage process check."
    fi
    echo "" >> "$LOG_FILE"
} # Added missing brace here

check_persistence_mechanisms() {
    gen_log "INFO: [Persistence] Checking common persistence mechanisms..."
    local found_persistence_issue=false

    gen_log "INFO: [Persistence] Checking Crontab contents."
    local cron_files=("/etc/crontab" "/etc/cron.d/*" "/var/spool/cron/*" "/var/spool/cron/crontabs/*")
    for cron_file_pattern in "${cron_files[@]}"; do
        find $(dirname "$cron_file_pattern") -name "$(basename "$cron_file_pattern")" -type f -print0 2>/dev/null | while IFS= read -r -d $'\0' file; do
            if [ -f "$file" ] && [ -r "$file" ]; then
                gen_log "INFO: [Persistence] Checking cron file: $file"
                if grep -Eiq "$(IFS='|'; echo "${SUSPICIOUS_NAMES_PATHS[*]}")|bpfdoor|kthreadd|initd_char" "$file"; then
                    gen_log "WARN: [Persistence] Suspicious pattern found in cron file '$file'."
                    grep -Ein "$(IFS='|'; echo "${SUSPICIOUS_NAMES_PATHS[*]}")|bpfdoor|kthreadd|initd_char" "$file" >> "$LOG_FILE"
                    found_persistence_issue=true
                fi
            fi
        done
    done
    
    gen_log "INFO: [Persistence] Checking for suspicious services in Systemd service list."
    local systemd_paths=("/etc/systemd/system" "/usr/lib/systemd/system" "/run/systemd/system" "$HOME/.config/systemd/user")
    for dir in "${systemd_paths[@]}"; do
        if [ -d "$dir" ]; then
            #Search for suspicious ExecStart, Description, etc. within service files
            grep -rliE "$(IFS='|'; echo "${SUSPICIOUS_NAMES_PATHS[*]}")|ExecStart=.*/tmp/|ExecStart=.*/dev/shm/|bpfdoor|kthreadd" "$dir" 2>/dev/null | while read -r service_file; do
                gen_log "WARN: [Persistence] Suspicious pattern found in Systemd service file '$service_file'."
                grep -Ei "$(IFS='|'; echo "${SUSPICIOUS_NAMES_PATHS[*]}")|ExecStart=.*/tmp/|ExecStart=.*/dev/shm/|bpfdoor|kthreadd" "$service_file" >> "$LOG_FILE"
                found_persistence_issue=true
            done
        fi
    done

    gen_log "INFO: [Persistence] Checking RC scripts (/etc/rc.local, /etc/init.d/*)."
    local rc_scripts=("/etc/rc.local" "/etc/init.d/*")
    for rc_item_pattern in "${rc_scripts[@]}"; do
        find $(dirname "$rc_item_pattern") -name "$(basename "$rc_item_pattern")" -type f -print0 2>/dev/null | while IFS= read -r -d $'\0' rc_file; do
            if [ -e "$rc_file" ] && [ -r "$rc_file" ]; then
                if grep -Eiq "$(IFS='|'; echo "${SUSPICIOUS_NAMES_PATHS[*]}")|/tmp/|/dev/shm/|bpfdoor" "$rc_file"; then
                    gen_log "WARN: [Persistence] Suspicious pattern found in RC script '$rc_file'."
                    grep -Ein "$(IFS='|'; echo "${SUSPICIOUS_NAMES_PATHS[*]}")|/tmp/|/dev/shm/|bpfdoor" "$rc_file" >> "$LOG_FILE"
                    found_persistence_issue=true
                fi
            fi
        done
    done

    #LD_PRELOAD (environment variables and files) check
    gen_log "INFO: [Persistence] Checking LD_PRELOAD settings to detect potential hijacking."
    local ld_preload_output_tmp="./ld_preload_check.txt"
    echo "" > "$ld_preload_output_tmp"

    #Check LD_PRELOAD in environment variables of running processes
    for proc_env_file in /proc/[0-9]*/environ; do
        if [ -r "$proc_env_file" ]; then
            tr '\0' '\n' < "$proc_env_file" 2>/dev/null | grep -H --label="$proc_env_file" '^LD_PRELOAD=' >> "$ld_preload_output_tmp"
        fi
    done

    #Check system-wide /etc/ld.so.preload file
    if [ -f "/etc/ld.so.preload" ]; then
        if [ -s "/etc/ld.so.preload" ]; then
            gen_log "WARN: [Persistence] Global LD_PRELOAD configuration file (/etc/ld.so.preload) has content."
            echo "--- /etc/ld.so.preload content ---" >> "$ld_preload_output_tmp"
            cat "/etc/ld.so.preload" >> "$ld_preload_output_tmp"
            echo "--- End of /etc/ld.so.preload content ---" >> "$ld_preload_output_tmp"
        else
            gen_log "INFO: [Persistence] Global LD_PRELOAD configuration file (/etc/ld.so.preload) is empty."
        fi
    fi
    
    if [ -n "$LD_PRELOAD" ]; then
        gen_log "WARN: [Persistence] LD_PRELOAD variable is set in the current shell environment: $LD_PRELOAD"
        echo "Current shell LD_PRELOAD: $LD_PRELOAD" >> "$ld_preload_output_tmp"
    fi

    if [ -s "$ld_preload_output_tmp" ]; then
        gen_log "WARN: [Persistence] LD_PRELOAD related settings detected. Check the content below:"
        cat "$ld_preload_output_tmp" | tee -a "$LOG_FILE"
        found_persistence_issue=true
    else
        gen_log "INFO: [Persistence] No significant LD_PRELOAD settings found in active processes, global settings, or current shell."
    fi

    if [ "$found_persistence_issue" = false ]; then
        gen_log "INFO: [Persistence] No suspicious items found in major persistence mechanisms."
    fi
    echo "" >> "$LOG_FILE"
}

check_process_masquerading() {
    gen_log "INFO: [Process Masquerading] Checking for suspected process masquerading cases."
    local masquerade_output_tmp="./masquerade_process.txt"
    echo "" > "$masquerade_output_tmp"
    local found_masquerade=false

    for pid_path in /proc/[0-9]*; do
        if [ -d "$pid_path" ]; then
            local pid=$(basename "$pid_path")
            local comm_file="$pid_path/comm"
            local cmdline_file="$pid_path/cmdline"

            if [[ -r "$comm_file" && -r "$cmdline_file" ]]; then
                local comm_val=$(cat "$comm_file" 2>/dev/null)
                local cmd_first_arg=$(tr -d '\0' < "$cmdline_file" 2>/dev/null | xargs -n1 echo 2>/dev/null | head -n1)
                local base_cmd_first_arg=$(basename "$cmd_first_arg" 2>/dev/null)
                local full_cmdline=$(tr -d '\0' < "$cmdline_file" 2>/dev/null | head -c 256)

                #Suspect if process name and executable file name differ
                if [[ -n "$comm_val" && -n "$base_cmd_first_arg" && "$comm_val" != "$base_cmd_first_arg" ]]; then
                    if ! [[ "$comm_val" == "["*"]" || "$base_cmd_first_arg" == "["*"]" ]]; then
                        if ! ( [[ "$comm_val" == "java" && ( "$base_cmd_first_arg" == "java" || "$base_cmd_first_arg" == "" ) ]] || \
                               [[ "$comm_val" == "python"* && ( "$base_cmd_first_arg" == "python"* || "$base_cmd_first_arg" == "" ) ]] || \
                               [[ "$comm_val" == "bash" && ( "$base_cmd_first_arg" == "bash" || "$base_cmd_first_arg" == "" ) ]] || \
                               [[ "$comm_val" == "sh" && ( "$base_cmd_first_arg" == "sh" || "$base_cmd_first_arg" == "" ) ]] ) ; then
                            echo "[!] Suspected masquerading process: PID $pid, Comm: '$comm_val', Cmdline Basename: '$base_cmd_first_arg', Full Cmdline: '$full_cmdline'" >> "$masquerade_output_tmp"
                            found_masquerade=true
                        fi
                    fi
                fi
            fi
        fi
    done

    if [ "$found_masquerade" = true ]; then
        gen_log "WARN: [Process Masquerading] Suspicious processes found. Details are as follows:"
        cat "$masquerade_output_tmp" | tee -a "$LOG_FILE"
    else
        gen_log "INFO: [Process Masquerading] No suspicious processes found."
    fi
    echo "" >> "$LOG_FILE"
}

check_temp_elf_files() {
    if [ "$FILE_CMD_INSTALLED" -ne 0 ]; then
        gen_log "WARN: 'file' command not available, skipping temporary path ELF file check."
        return
    fi
    gen_log "INFO: [Temp ELF] Checking executable files (ELF) in temporary paths (/tmp, /var/tmp, /dev/shm, /run)."
    local temp_elf_output="./temp_elf_files.txt"
    echo "" > "$temp_elf_output"
    local found_temp_elf=false
    
    #Check /tmp, /var/tmp, /dev/shm, /run
    local TEMP_PATHS_TO_SCAN=("/tmp" "/var/tmp" "/dev/shm" "/run")
    for temp_path in "${TEMP_PATHS_TO_SCAN[@]}"; do
        if [ -d "$temp_path" ]; then
            #Higher maxdepth numbers will take longer
            find "$temp_path" -maxdepth 1 -type f -print0 2>/dev/null | xargs -0 -r file -N 2>/dev/null | grep ': ELF' >> "$temp_elf_output"
            find "$temp_path" -maxdepth 1 -name ".*" -type f -print0 2>/dev/null | xargs -0 -r file -N 2>/dev/null | grep ': ELF' >> "$temp_elf_output"
        fi
    done

    if [ -s "$temp_elf_output" ]; then
        sort -u "$temp_elf_output" -o "$temp_elf_output"
        gen_log "WARN: [Temp ELF] The following ELF executable files were found in temporary paths. Check for possible malware hiding:"
        cat "$temp_elf_output" | tee -a "$LOG_FILE"
        found_temp_elf=true
    fi

    if [ "$found_temp_elf" = false ]; then
        gen_log "INFO: [Temp ELF] No suspicious ELF executable files found in temporary paths."
    fi
    echo "" >> "$LOG_FILE"
}

check_recent_modified_executables() {
    gen_log "INFO: [Recent Files] Checking major executable files/libraries created or modified in the last 3 days. (Normal file creation and modification will also be detected. Review is necessary.)"
    local recent_files_output_tmp="./recent_exec_files.txt"
    echo "" > "$recent_files_output_tmp"
    local found_recent_files=false

    #Excluded search paths (to prevent excessive time consumption) /proc, /sys, /dev, etc. virtual file systems excluded
    local excluded_paths_find="-path /proc -o -path /sys -o -path /dev -o -path /run/user -o -path /snap -o -path /var/lib/docker -o -path /var/log"
    find / \( $excluded_paths_find \) -prune -o -type f -perm /111 -mtime -3 -print0 2>/dev/null | xargs -0 -r ls -alhd >> "$recent_files_output_tmp" 2>/dev/null
    
    #Files with specific extensions (.so, .bin, .elf, etc.) modified within the last 3 days
    find / \( $excluded_paths_find \) -prune -o -type f \( -iname "*.so" -o -iname "*.bin" -o -iname "*.elf" -o -iname "*.so.*" \) -mtime -3 -print0 2>/dev/null | xargs -0 -r ls -alhd >> "$recent_files_output_tmp" 2>/dev/null

    if [ -s "$recent_files_output_tmp" ]; then
        sort -u "$recent_files_output_tmp" -o "$recent_files_output_tmp"
        gen_log "WARN: [Recent Files] Executable files or libraries modified within the last 3 days were found. (This could be normal activity like system updates, so review carefully):"
        cat "$recent_files_output_tmp" | tee -a "$LOG_FILE"
        found_recent_files=true
    fi

    if [ "$found_recent_files" = false ]; then
        gen_log "INFO: [Recent Files] No executable files/libraries modified in major paths within the last 3 days were found. (Results may vary depending on excluded folders, etc.)"
    fi
    echo "" >> "$LOG_FILE"
}

check_hidden_processes() {
    gen_log "INFO: [Hidden Process] Attempting to detect hidden processes."
    local hidden_procs_output_tmp="./hidden_procs.txt"
    echo "" > "$hidden_procs_output_tmp"
    local found_hidden_procs=false 
    local logged_a_diff_pid=false 

    local ps_pids=$(ps -e -o pid= --no-headers 2>/dev/null | sort -n | uniq)
    local proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | sed 's/\/proc\///g' | sort -n | uniq)
    if [ -z "$ps_pids" ] || [ -z "$proc_pids" ]; then
        gen_log "WARN: [Hidden Process] Failed to get ps or /proc list, skipping hidden process check."
        return
    fi
    
    local diff_pids=$(comm -13 <(echo "$ps_pids") <(echo "$proc_pids"))

    if [ -n "$diff_pids" ]; then
        for pid_val in $diff_pids; do
            local cmdline_path="/proc/$pid_val/cmdline"
            local comm_path="/proc/$pid_val/comm"
            local exe_path="/proc/$pid_val/exe"
            local cmdline_content="N/A"
            local comm_content="N/A"
            local exe_link="N/A"
            
            if [ -r "$cmdline_path" ]; then
                local original_cmdline_content=$(tr -d '\0' < "$cmdline_path" | head -c 256)
                cmdline_content="$original_cmdline_content"
                if [ -z "$original_cmdline_content" ]; then
                    cmdline_content="(empty cmdline)"
                fi
            else
                cmdline_content="(cannot read cmdline)"
            fi

            if [ -r "$comm_path" ]; then
                comm_content=$(cat "$comm_path" 2>/dev/null)
                if [ -z "$comm_content" ]; then
                    comm_content="(empty comm)"
                fi
            else
                comm_content="(cannot read comm)"
            fi

            if [ -L "$exe_path" ]; then
                local original_exe_link=$(readlink -f "$exe_path" 2>/dev/null)
                exe_link="$original_exe_link"
                if [ -z "$original_exe_link" ]; then
                    exe_link="(readlink failed)"
                fi
            elif [ -e "$exe_path" ]; then
                exe_link="(not a symlink but exists)"
            else
                exe_link="(exe path does not exist)"
            fi
            
            local is_likely_noise=false
            if ( [ "$cmdline_content" = "(empty cmdline)" ] || \
                 [ "$cmdline_content" = "(cannot read cmdline)" ] ) && \
               ( [ "$exe_link" = "(readlink failed)" ] || \
                 [ "$exe_link" = "(exe path does not exist)" ] || \
                 [ "$exe_link" = "N/A" ] ); then
                is_likely_noise=true
            fi

            if [ "$is_likely_noise" = false ]; then
                echo "  PID: $pid_val, Comm: '$comm_content', Cmdline: '$cmdline_content', Exe: '$exe_link'" >> "$hidden_procs_output_tmp"
                logged_a_diff_pid=true
            fi
        done

        if [ "$logged_a_diff_pid" = true ]; then
            gen_log "WARN: [Hidden Process] PIDs found in /proc directory but not in 'ps' list. (Could be short-lived processes or potential hiding. Review lines that are NOT typical kernel threads):"
            found_hidden_procs=true
            cat "$hidden_procs_output_tmp" | tee -a "$LOG_FILE" 
        fi
    fi

    if [ "$found_hidden_procs" = false ]; then
        gen_log "INFO: [Hidden Process] No suspicious hidden processes (or only filtered typical kernel/transient threads) were found by simple comparison between 'ps' and /proc lists."
    fi
    echo "" >> "$LOG_FILE"
}

main() {
    display_banner_and_init

    gen_log "========== Starting BPFDoor Malware Scan =========="
    echo "" >> "$LOG_FILE"

    # Remove comments if necessary. Remove the "#"" comment before setup_and run_yara_scan in the main() function. (Yara must be installed.)
    # setup_and_run_yara_scan
    check_files_by_hash
    check_suspicious_processes_and_files
    check_network_connections
    check_bpf_artifacts
    check_persistence_mechanisms
    check_process_masquerading
    check_temp_elf_files
    #Possibility of false positives // Disable if necessary
    check_recent_modified_executables
    #Possibility of false positives // Disable if necessary
    check_hidden_processes

    gen_log "========== BPFDoor Malware Scan Complete =========="
    echo "" >> "$LOG_FILE"
    gen_log "All checks have been completed. Please refer to the log file '$LOG_FILE' and screen output for results."
    gen_log "WARN: This script is an auxiliary detection tool and may not detect all BPFDoor variants or malicious activities."
    gen_log "After reviewing the results, you may delete the created folders and files (e.g., rm -rf {folder_name})."
    
    echo ""
    echo "BPFDoor scan complete. Detailed log: $LOG_FILE"
}

main

exit 0