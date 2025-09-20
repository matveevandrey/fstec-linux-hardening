#!/bin/bash
# fstec-linux-hardening.sh
# Полное соответствие методичке ФСТЭК от 25.12.2022
# Поддержка: Debian 12, Ubuntu 20.04+, RHEL 8+, Astra Linux, Альт СП 10

set -uo pipefail
IFS=$'\n\t'

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Переменные
MODE="test"   # по умолчанию тест
VERBOSE=0
LOG_FILE="/var/log/fstec-hardening-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/fstec-backup-$(date +%Y%m%d)"
OS_IMPACT_LEVEL="all"  # all, safe, medium, dangerous
RISK_LEVEL="all"       # all, low, medium, high, critical

# Карта влияния на работу ОС для каждой настройки
declare -A OS_IMPACT_MAP=(
    ["2.1.1"]="safe"       # Запрет пустых паролей
    ["2.1.2"]="safe"       # Запрет root входа по SSH
    ["2.2.1"]="safe"       # Ограничение команды su
    ["2.2.2"]="safe"       # Настройка sudo для wheel
    ["2.3.1"]="safe"       # Права доступа к системным файлам
    ["2.3.2"]="safe"       # Права на файлы cron
    ["2.3.3"]="medium"     # Аудит SUID/SGID приложений
    ["2.3.4"]="safe"       # Права на скрытые файлы в home
    ["2.3.5"]="safe"       # Права на домашние директории
    ["2.4.1"]="safe"       # kernel.dmesg_restrict
    ["2.4.2"]="safe"       # kernel.kptr_restrict
    ["2.4.3"]="safe"       # net.core.bpf_jit_harden
    ["2.5.1"]="medium"     # kernel.perf_event_paranoid
    ["2.5.2"]="medium"     # kernel.kexec_load_disabled
    ["2.5.3"]="dangerous"  # user.max_user_namespaces
    ["2.5.4"]="medium"     # kernel.unprivileged_bpf_disabled
    ["2.5.5"]="medium"     # vm.unprivileged_userfaultfd
    ["2.5.6"]="safe"       # dev.tty.ldisc_autoload
    ["2.5.7"]="safe"       # vm.mmap_min_addr
    ["2.5.8"]="safe"       # kernel.randomize_va_space
    ["2.6.1"]="medium"     # kernel.yama.ptrace_scope
    ["2.6.2"]="safe"       # fs.protected_symlinks
    ["2.6.3"]="safe"       # fs.protected_hardlinks
    ["2.6.4"]="safe"       # fs.protected_fifos
    ["2.6.5"]="safe"       # fs.protected_regular
    ["2.6.6"]="safe"       # fs.suid_dumpable
    ["kernel.init_on_alloc"]="safe"
    ["kernel.slab_nomerge"]="safe"
    ["kernel.mitigations"]="medium"
    ["kernel.iommu_force"]="dangerous"
    ["kernel.iommu_strict"]="dangerous"
    ["kernel.iommu_passthrough"]="dangerous"
    ["kernel.randomize_kstack_offset"]="safe"
    ["kernel.vsyscall_none"]="medium"
    ["kernel.tsx_off"]="medium"
    ["kernel.debugfs_off"]="safe"
)

# Карта степени риска незакрытия уязвимости
declare -A RISK_MAP=(
    ["2.1.1"]="high"       # Высокий риск при незакрытии
    ["2.1.2"]="high"       # Высокий риск при незакрытии
    ["2.2.1"]="medium"     # Средний риск при незакрытии
    ["2.2.2"]="medium"     # Средний риск при незакрытии
    ["2.3.1"]="high"       # Высокий риск при незакрытии
    ["2.3.2"]="medium"     # Средний риск при незакрытии
    ["2.3.3"]="medium"     # Средний риск при незакрытии
    ["2.3.4"]="low"        # Низкий риск при незакрытии
    ["2.3.5"]="medium"     # Средний риск при незакрытии
    ["2.4.1"]="high"       # Высокий риск при незакрытии
    ["2.4.2"]="high"       # Высокий риск при незакрытии
    ["2.4.3"]="medium"     # Средний риск при незакрытии
    ["2.5.1"]="high"       # Высокий риск при незакрытии
    ["2.5.2"]="medium"     # Средний риск при незакрытии
    ["2.5.3"]="critical"   # Критический риск при незакрытии
    ["2.5.4"]="high"       # Высокий риск при незакрытии
    ["2.5.5"]="medium"     # Средний риск при незакрытии
    ["2.5.6"]="low"        # Низкий риск при незакрытии
    ["2.5.7"]="medium"     # Средний риск при незакрытии
    ["2.5.8"]="high"       # Высокий риск при незакрытии
    ["2.6.1"]="high"       # Высокий риск при незакрытии
    ["2.6.2"]="medium"     # Средний риск при незакрытии
    ["2.6.3"]="medium"     # Средний риск при незакрытии
    ["2.6.4"]="low"        # Низкий риск при незакрытии
    ["2.6.5"]="low"        # Низкий риск при незакрытии
    ["2.6.6"]="medium"     # Средний риск при незакрытии
    ["kernel.init_on_alloc"]="high"
    ["kernel.slab_nomerge"]="medium"
    ["kernel.mitigations"]="high"
    ["kernel.iommu_force"]="critical"
    ["kernel.iommu_strict"]="critical"
    ["kernel.iommu_passthrough"]="critical"
    ["kernel.randomize_kstack_offset"]="high"
    ["kernel.vsyscall_none"]="high"
    ["kernel.tsx_off"]="medium"
    ["kernel.debugfs_off"]="low"
)

# По умолчанию все секции
SECTIONS=("2.1" "2.2" "2.3" "2.4" "2.5" "2.6" "kernel")

# Подсчет успешных/всех проверок
TOTAL_CHECKS=0
SUCCESS_CHECKS=0
ERROR_CHECKS=0

# Счетчики для анализа рисков
CRITICAL_RISK_TOTAL=0
HIGH_RISK_TOTAL=0
MEDIUM_RISK_TOTAL=0
LOW_RISK_TOTAL=0
CRITICAL_RISK_SUCCESS=0
HIGH_RISK_SUCCESS=0
MEDIUM_RISK_SUCCESS=0
LOW_RISK_SUCCESS=0

# Определение дистрибутива
OS_TYPE="unknown"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    
    # Определяем тип ОС
    if [[ "$OS_ID" == "alt" ]] || grep -qi "alt" /etc/os-release || grep -qi "alt" /etc/issue; then
        OS_TYPE="alt"
    elif [[ "$OS_ID" == "debian" || "$OS_ID" == "ubuntu" ]]; then
        OS_TYPE="debian"
    elif [[ "$OS_ID" == "centos" || "$OS_ID" == "rhel" || "$OS_ID" == "fedora" ]]; then
        OS_TYPE="rhel"
    elif [[ "$OS_ID" == "astra" ]]; then
        OS_TYPE="astra"
    fi
else
    OS_ID="unknown"
    OS_VERSION="unknown"
fi

# Функции логирования
log() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }

# Функция для определения влияния на ОС
get_os_impact() {
    local check_id="$1"
    echo "${OS_IMPACT_MAP[$check_id]:-"unknown"}"
}

# Функция для определения степени риска
get_risk_level() {
    local check_id="$1"
    echo "${RISK_MAP[$check_id]:-"unknown"}"
}

# Функция для проверки соответствия уровню влияния на ОС
should_apply_os_impact() {
    local os_impact="$1"
    case "$OS_IMPACT_LEVEL" in
        "all") return 0 ;;
        "safe") [[ "$os_impact" == "safe" ]] && return 0 ;;
        "medium") [[ "$os_impact" == "safe" || "$os_impact" == "medium" ]] && return 0 ;;
        "dangerous") return 0 ;;
    esac
    return 1
}

# Функция для проверки соответствия уровню риска
should_apply_risk() {
    local risk_level="$1"
    case "$RISK_LEVEL" in
        "all") return 0 ;;
        "low") [[ "$risk_level" == "low" ]] && return 0 ;;
        "medium") [[ "$risk_level" == "low" || "$risk_level" == "medium" ]] && return 0 ;;
        "high") [[ "$risk_level" == "low" || "$risk_level" == "medium" || "$risk_level" == "high" ]] && return 0 ;;
        "critical") return 0 ;;
    esac
    return 1
}

# Функции для работы с сервисами
restart_service() {
    local service="$1"
    if [[ "$OS_TYPE" == "alt" ]]; then
        /sbin/service "$service" restart >> "$LOG_FILE" 2>&1
    else
        systemctl restart "$service" >> "$LOG_FILE" 2>&1
    fi
}

enable_service() {
    local service="$1"
    if [[ "$OS_TYPE" == "alt" ]]; then
        /sbin/chkconfig "$service" on >> "$LOG_FILE" 2>&1
    else
        systemctl enable "$service" >> "$LOG_FILE" 2>&1
    fi
}

# Функция обновления GRUB
update_grub_config() {
    if [[ "$OS_TYPE" == "alt" ]]; then
        if command -v grub2-mkconfig >/dev/null 2>&1; then
            grub2-mkconfig -o /boot/grub2/grub.cfg >> "$LOG_FILE" 2>&1
        elif command -v update-grub >/dev/null 2>&1; then
            update-grub >> "$LOG_FILE" 2>&1
        else
            warning "Не найдена команда для обновления GRUB"
        fi
    else
        if command -v update-grub >/dev/null 2>&1; then
            update-grub >> "$LOG_FILE" 2>&1
        elif command -v grub2-mkconfig >/dev/null 2>&1; then
            grub2-mkconfig -o /boot/grub2/grub.cfg >> "$LOG_FILE" 2>&1
        fi
    fi
}

# Универсальная функция проверки/применения
apply_or_test() {
    local check_id="$1"
    local check_cmd="$2"
    local apply_cmd="$3"
    local desc="$4"
    
    local os_impact=$(get_os_impact "$check_id")
    local risk_level=$(get_risk_level "$check_id")
    
    # Проверяем, соответствует ли уровень влияния на ОС фильтру
    if ! should_apply_os_impact "$os_impact"; then
        [[ $VERBOSE -eq 1 ]] && log "Пропуск ($check_id): $desc (влияние на ОС: $os_impact)"
        return 0
    fi
    
    # Проверяем, соответствует ли уровень риска фильтру
    if ! should_apply_risk "$risk_level"; then
        [[ $VERBOSE -eq 1 ]] && log "Пропуск ($check_id): $desc (риск: $risk_level)"
        return 0
    fi

    TOTAL_CHECKS=$((TOTAL_CHECKS+1))
    
    # Обновляем счетчики по степени риска
    case "$risk_level" in
        "critical") CRITICAL_RISK_TOTAL=$((CRITICAL_RISK_TOTAL+1)) ;;
        "high") HIGH_RISK_TOTAL=$((HIGH_RISK_TOTAL+1)) ;;
        "medium") MEDIUM_RISK_TOTAL=$((MEDIUM_RISK_TOTAL+1)) ;;
        "low") LOW_RISK_TOTAL=$((LOW_RISK_TOTAL+1)) ;;
    esac

    if [[ "$MODE" == "test" ]]; then
        if eval "$check_cmd" >/dev/null 2>&1; then
            success "$desc (влияние на ОС: $os_impact, риск: $risk_level)"
            SUCCESS_CHECKS=$((SUCCESS_CHECKS+1))
            
            # Обновляем счетчики успешных проверок по степени риска
            case "$risk_level" in
                "critical") CRITICAL_RISK_SUCCESS=$((CRITICAL_RISK_SUCCESS+1)) ;;
                "high") HIGH_RISK_SUCCESS=$((HIGH_RISK_SUCCESS+1)) ;;
                "medium") MEDIUM_RISK_SUCCESS=$((MEDIUM_RISK_SUCCESS+1)) ;;
                "low") LOW_RISK_SUCCESS=$((LOW_RISK_SUCCESS+1)) ;;
            esac
            
            return 0
        else
            warning "$desc (влияние на ОС: $os_impact, риск: $risk_level)"
            return 1
        fi
    else
        log "Применение: $desc (влияние на ОС: $os_impact, риск: $risk_level)"
        if [[ $VERBOSE -eq 1 ]]; then
            echo -e "${BLUE}[CMD]${NC} $apply_cmd" | tee -a "$LOG_FILE"
        fi
        if eval "$apply_cmd" >>"$LOG_FILE" 2>&1; then
            success "Применено: $desc"
            return 0
        else
            error "Ошибка применения: $desc"
            ERROR_CHECKS=$((ERROR_CHECKS+1))
            return 1
        fi
    fi
}

# Безопасное выполнение команд
safe_exec() {
    local cmd="$1"
    local desc="$2"
    
    if eval "$cmd" >>"$LOG_FILE" 2>&1; then
        log "Выполнено: $desc"
        return 0
    else
        error "Ошибка выполнения: $desc"
        ERROR_CHECKS=$((ERROR_CHECKS+1))
        return 1
    fi
}

# Бэкап
create_backup() {
    log "Создание бэкапа в $BACKUP_DIR"
    safe_exec "mkdir -p '$BACKUP_DIR'" "Создание директории бэкапа"
    safe_exec "cp -p /etc/ssh/sshd_config '$BACKUP_DIR/'" "Бэкап sshd_config"
    safe_exec "cp -p /etc/pam.d/su '$BACKUP_DIR/'" "Бэкап PAM su"
    safe_exec "cp -p /etc/sudoers '$BACKUP_DIR/'" "Бэкап sudoers"
    safe_exec "cp -p /etc/default/grub '$BACKUP_DIR/' 2>/dev/null || true" "Бэкап grub"
    safe_exec "cp -p /etc/sysctl.conf '$BACKUP_DIR/' 2>/dev/null || true" "Бэкап sysctl.conf"
    safe_exec "sysctl -a > '$BACKUP_DIR/sysctl-backup.txt' 2>/dev/null || true" "Бэкап sysctl настроек"
    
    # Бэкап специфичных для Альт файлов
    if [[ "$OS_TYPE" == "alt" ]]; then
        safe_exec "cp -p /boot/grub2/grub.cfg '$BACKUP_DIR/' 2>/dev/null || true" "Бэкап grub.cfg"
        safe_exec "cp -p /etc/sysconfig/ '$BACKUP_DIR/sysconfig-backup/' 2>/dev/null || true" "Бэкап sysconfig"
    fi
}

########## 2.1. Авторизация ##########
section_2_1() {
    log "=== Секция 2.1: Авторизация ==="
    apply_or_test "2.1.1" \
        "! awk -F: '\$2 == \"\" {print \$1}' /etc/shadow | grep -q ." \
        "sed -i 's/nullok//g' /etc/pam.d/* && passwd -l \$(awk -F: '\$2 == \"\" {print \$1}' /etc/shadow) 2>/dev/null || true" \
        "Запрет пустых паролей"
    
    apply_or_test "2.1.2" \
        "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config" \
        "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && restart_service sshd" \
        "Запрет root входа по SSH"
}

########## 2.2. Привилегии ##########
section_2_2() {
    log "=== Секция 2.2: Ограничение привилегий ==="
    apply_or_test "2.2.1" \
        "grep -q 'auth required pam_wheel.so' /etc/pam.d/su" \
        "echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su && (grep -q '^wheel:' /etc/group || echo 'wheel:x:10:root' >> /etc/group)" \
        "Ограничение команды su"
    
    apply_or_test "2.2.2" \
        "grep -q '^%wheel' /etc/sudoers" \
        "echo '%wheel ALL=(ALL:ALL) ALL' >> /etc/sudoers" \
        "Настройка sudo для wheel"
}

########## 2.3. Права доступа ##########
section_2_3() {
    log "=== Секция 2.3: Права доступа к ФС ==="
    apply_or_test "2.3.1" \
        "[[ \$(stat -c '%a' /etc/passwd 2>/dev/null) == 644 ]] && [[ \$(stat -c '%a' /etc/group 2>/dev/null) == 644 ]] && [[ \$(stat -c '%a' /etc/shadow 2>/dev/null) =~ ^(0|640)$ ]]" \
        "chmod 644 /etc/passwd /etc/group 2>/dev/null || true; chmod 640 /etc/shadow 2>/dev/null || true; chown root:root /etc/passwd /etc/group /etc/shadow 2>/dev/null || true" \
        "Права доступа к /etc/passwd, /etc/group, /etc/shadow"
    
    apply_or_test "2.3.2" \
        "! find /etc/cron* /var/spool/cron -type f -executable ! -user root 2>/dev/null | head -5 | grep -q ." \
        "find /etc/cron* /var/spool/cron -type f -executable ! -user root -exec chmod go-w {} \\; 2>/dev/null || true" \
        "Права на файлы cron"
    
    apply_or_test "2.3.3" \
        "find / -xdev -type f -perm /6000 2>/dev/null | head -10 | xargs -I {} sh -c 'stat -c \"%a %U\" {} 2>/dev/null' | awk '\$1 ~ /[0-9][0-9][0-9][0-9]/ && \$2 != \"root\" {exit 1}' || true" \
        "find / -xdev -type f -perm /6000 ! -user root -exec chmod go-w {} \\; 2>/dev/null || true" \
        "Аудит SUID/SGID приложений"
    
    apply_or_test "2.3.4" \
        "! find /home -name '.bash_history' -o -name '.history' -o -name '.sh_history' -o -name '.bashrc' -o -name '.profile' -o -name '.rhosts' ! -perm 600 2>/dev/null | head -5 | grep -q ." \
        "find /home -name '.bash_history' -o -name '.history' -o -name '.sh_history' -o -name '.bashrc' -o -name '.profile' -o -name '.rhosts' -exec chmod go-rwx {} \\; 2>/dev/null || true" \
        "Права на скрытые файлы в home"
    
    apply_or_test "2.3.5" \
        "! find /home -maxdepth 1 -type d ! -perm 700 ! -user root 2>/dev/null | head -5 | grep -q ." \
        "find /home -maxdepth 1 -type d ! -perm 700 ! -user root -exec chmod 700 {} \\; 2>/dev/null || true" \
        "Права на домашние директории"
}

########## 2.4. Защита ядра ##########
section_2_4() {
    log "=== Секция 2.4: Усиление ядра ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    apply_or_test "2.4.1" "[[ \$(sysctl -n kernel.dmesg_restrict 2>/dev

########## 2.1. Авторизация ##########
section_2_1() {
    log "=== Секция 2.1: Авторизация ==="
    apply_or_test "2.1.1" \
        "! awk -F: '\$2 == \"\" {print \$1}' /etc/shadow | grep -q ." \
        "sed -i 's/nullok//g' /etc/pam.d/* && passwd -l \$(awk -F: '\$2 == \"\" {print \$1}' /etc/shadow) 2>/dev/null || true" \
        "Запрет пустых паролей"
    
    apply_or_test "2.1.2" \
        "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config" \
        "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && restart_service sshd" \
        "Запрет root входа по SSH"
}

########## 2.2. Привилегии ##########
section_2_2() {
    log "=== Секция 2.2: Ограничение привилегий ==="
    apply_or_test "2.2.1" \
        "grep -q 'auth required pam_wheel.so' /etc/pam.d/su" \
        "echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su && (grep -q '^wheel:' /etc/group || echo 'wheel:x:10:root' >> /etc/group)" \
        "Ограничение команды su"
    
    apply_or_test "2.2.2" \
        "grep -q '^%wheel' /etc/sudoers" \
        "echo '%wheel ALL=(ALL:ALL) ALL' >> /etc/sudoers" \
        "Настройка sudo для wheel"
}

########## 2.3. Права доступа ##########
section_2_3() {
    log "=== Секция 2.3: Права доступа к ФС ==="
    apply_or_test "2.3.1" \
        "[[ \$(stat -c '%a' /etc/passwd 2>/dev/null) == 644 ]] && [[ \$(stat -c '%a' /etc/group 2>/dev/null) == 644 ]] && [[ \$(stat -c '%a' /etc/shadow 2>/dev/null) =~ ^(0|640)$ ]]" \
        "chmod 644 /etc/passwd /etc/group 2>/dev/null || true; chmod 640 /etc/shadow 2>/dev/null || true; chown root:root /etc/passwd /etc/group /etc/shadow 2>/dev/null || true" \
        "Права доступа к /etc/passwd, /etc/group, /etc/shadow"
    
    apply_or_test "2.3.2" \
        "! find /etc/cron* /var/spool/cron -type f -executable ! -user root 2>/dev/null | head -5 | grep -q ." \
        "find /etc/cron* /var/spool/cron -type f -executable ! -user root -exec chmod go-w {} \\; 2>/dev/null || true" \
        "Права на файлы cron"
    
    apply_or_test "2.3.3" \
        "find / -xdev -type f -perm /6000 2>/dev/null | head -10 | xargs -I {} sh -c 'stat -c \"%a %U\" {} 2>/dev/null' | awk '\$1 ~ /[0-9][0-9][0-9][0-9]/ && \$2 != \"root\" {exit 1}' || true" \
        "find / -xdev -type f -perm /6000 ! -user root -exec chmod go-w {} \\; 2>/dev/null || true" \
        "Аудит SUID/SGID приложений"
    
    apply_or_test "2.3.4" \
        "! find /home -name '.bash_history' -o -name '.history' -o -name '.sh_history' -o -name '.bashrc' -o -name '.profile' -o -name '.rhosts' ! -perm 600 2>/dev/null | head -5 | grep -q ." \
        "find /home -name '.bash_history' -o -name '.history' -o -name '.sh_history' -o -name '.bashrc' -o -name '.profile' -o -name '.rhosts' -exec chmod go-rwx {} \\; 2>/dev/null || true" \
        "Права на скрытые файлы в home"
    
    apply_or_test "2.3.5" \
        "! find /home -maxdepth 1 -type d ! -perm 700 ! -user root 2>/dev/null | head -5 | grep -q ." \
        "find /home -maxdepth 1 -type d ! -perm 700 ! -user root -exec chmod 700 {} \\; 2>/dev/null || true" \
        "Права на домашние директории"
}

########## 2.4. Защита ядра ##########
section_2_4() {
    log "=== Секция 2.4: Усиление ядра ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    apply_or_test "2.4.1" "[[ \$(sysctl -n kernel.dmesg_restrict 2>/dev/null) == 1 ]]" \
        "echo 'kernel.dmesg_restrict = 1' >> '$sysctl_file'" "kernel.dmesg_restrict = 1"
    
    apply_or_test "2.4.2" "[[ \$(sysctl -n kernel.kptr_restrict 2>/dev/null) == 2 ]]" \
        "echo 'kernel.kptr_restrict = 2' >> '$sysctl_file'" "kernel.kptr_restrict = 2"
    
    apply_or_test "2.4.3" "[[ \$(sysctl -n net.core.bpf_jit_harden 2>/dev/null) == 2 ]]" \
        "echo 'net.core.bpf_jit_harden = 2' >> '$sysctl_file'" "net.core.bpf_jit_harden = 2"
}

########## 2.5. Уменьшение периметра атаки ##########
section_2_5() {
    log "=== Секция 2.5: Уменьшение периметра атаки ядра ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    apply_or_test "2.5.1" "[[ \$(sysctl -n kernel.perf_event_paranoid 2>/dev/null) == 3 ]]" \
        "echo 'kernel.perf_event_paranoid = 3' >> '$sysctl_file'" "kernel.perf_event_paranoid = 3"
    
    apply_or_test "2.5.2" "[[ \$(sysctl -n kernel.kexec_load_disabled 2>/dev/null) == 1 ]]" \
        "echo 'kernel.kexec_load_disabled = 1' >> '$sysctl_file'" "kernel.kexec_load_disabled = 1"
    
    apply_or_test "2.5.3" "[[ \$(sysctl -n user.max_user_namespaces 2>/dev/null) == 0 ]]" \
        "echo 'user.max_user_namespaces = 0' >> '$sysctl_file'" "user.max_user_namespaces = 0"
    
    apply_or_test "2.5.4" "[[ \$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null) == 1 ]]" \
        "echo 'kernel.unprivileged_bpf_disabled = 1' >> '$sysctl_file'" "kernel.unprivileged_bpf_disabled = 1"
    
    apply_or_test "2.5.5" "[[ \$(sysctl -n vm.unprivileged_userfaultfd 2>/dev/null) == 0 ]]" \
        "echo 'vm.unprivileged_userfaultfd = 0' >> '$sysctl_file'" "vm.unprivileged_userfaultfd = 0"
    
    apply_or_test "2.5.6" "[[ \$(sysctl -n dev.tty.ldisc_autoload 2>/dev/null) == 0 ]]" \
        "echo 'dev.tty.ldisc_autoload = 0' >> '$sysctl_file'" "dev.tty.ldisc_autoload = 0"
    
    apply_or_test "2.5.7" "[[ \$(sysctl -n vm.mmap_min_addr 2>/dev/null) -ge 4096 ]]" \
        "echo 'vm.mmap_min_addr = 65536' >> '$sysctl_file'" "vm.mmap_min_addr >= 4096"
    
    apply_or_test "2.5.8" "[[ \$(sysctl -n kernel.randomize_va_space 2>/dev/null) == 2 ]]" \
        "echo 'kernel.randomize_va_space = 2' >> '$sysctl_file'" "kernel.randomize_va_space = 2"
}

########## 2.6. Пользовательское пространство ##########
section_2_6() {
    log "=== Секция 2.6: Пользовательское пространство ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    apply_or_test "2.6.1" "[[ \$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null) == 3 ]]" \
        "echo 'kernel.yama.ptrace_scope = 3' >> '$sysctl_file'" "kernel.yama.ptrace_scope = 3"
    
    apply_or_test "2.6.2" "[[ \$(sysctl -n fs.protected_symlinks 2>/dev/null) == 1 ]]" \
        "echo 'fs.protected_symlinks = 1' >> '$sysctl_file'" "fs.protected_symlinks = 1"
    
    apply_or_test "2.6.3" "[[ \$(sysctl -n fs.protected_hardlinks 2>/dev/null) == 1 ]]" \
        "echo 'fs.protected_hardlinks = 1' >> '$sysctl_file'" "fs.protected_hardlinks = 1"
    
    apply_or_test "2.6.4" "[[ \$(sysctl -n fs.protected_fifos 2>/dev/null) == 2 ]]" \
        "echo 'fs.protected_fifos = 2' >> '$sysctl_file'" "fs.protected_fifos = 2"
    
    apply_or_test "2.6.5" "[[ \$(sysctl -n fs.protected_regular 2>/dev/null) == 2 ]]" \
        "echo 'fs.protected_regular = 2' >> '$sysctl_file'" "fs.protected_regular = 2"
    
    apply_or_test "2.6.6" "[[ \$(sysctl -n fs.suid_dumpable 2>/dev/null) == 0 ]]" \
        "echo 'fs.suid_dumpable = 0' >> '$sysctl_file'" "fs.suid_dumpable = 0"
}

########## Параметры загрузки ядра ##########
configure_kernel_params() {
    log "=== Секция kernel: Параметры загрузки ядра ==="
    
    local grub_file=""
    if [[ -f /etc/default/grub ]]; then
        grub_file="/etc/default/grub"
    elif [[ -f /boot/grub2/grub.cfg ]] && [[ "$OS_TYPE" == "alt" ]]; then
        warning "Альт Linux: редактирование /boot/grub2/grub.cfg напрямую"
        grub_file="/boot/grub2/grub.cfg"
    else
        warning "Файл конфигурации GRUB не найден, пропускаем параметры ядра"
        return
    fi
    
    apply_or_test "kernel.init_on_alloc" "grep -q 'init_on_alloc=1' /proc/cmdline" \
        "if ! grep -q \"init_on_alloc=1\" \"$grub_file\"; then sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 init_on_alloc=1\"/' \"$grub_file\"; fi" \
        "Параметр ядра: init_on_alloc=1"
    
    apply_or_test "kernel.slab_nomerge" "grep -q 'slab_nomerge' /proc/cmdline" \
        "if ! grep -q \"slab_nomerge\" \"$grub_file\"; then sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 slab_nomerge\"/' \"$grub_file\"; fi" \
        "Параметр ядра: slab_nomerge"
    
    apply_or_test "kernel.mitigations" "grep -q 'mitigations=auto,nosmt' /proc/cmdline" \
        "if ! grep -q \"mitigations=auto,nosmt\" \"$grub_file\"; then sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 mitigations=auto,nosmt\"/' \"$grub_file\"; fi" \
        "Параметр ядра: mitigations=auto,nosmt"
    
    # Для не-Альт систем добавляем дополнительные параметры
    if [[ "$OS_TYPE" != "alt" ]]; then
        apply_or_test "kernel.iommu_force" "grep -q 'iommu=force' /proc/cmdline" \
            "if ! grep -q \"iommu=force\" \"$grub_file\"; then sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 iommu=force\"/' \"$grub_file\"; fi" \
            "Параметр ядра: iommu=force"
        
        apply_or_test "kernel.iommu_strict" "grep -q 'iommu.strict=1' /proc/cmdline" \
            "if ! grep -q \"iommu.strict=1\" \"$grub_file\"; then sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 iommu.strict=1\"/' \"$grub_file\"; fi" \
            "Параметр ядра: iommu.strict=1"
        
        apply_or_test "kernel.iommu_passthrough" "grep -q 'iommu.passthrough=0' /proc/cmdline" \
            "if ! grep -q \"iommu.passthrough=0\" \"$grub_file\"; then sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 iommu.passthrough=0\"/' \"$grub_file\"; fi" \
            "Параметр ядра: iommu.passthrough=0"
        
        apply_or_test "kernel.randomize_kstack_offset" "grep -q 'randomize_kstack_offset=1' /proc/cmdline" \
            "if ! grep -q \"randomize_kstack_offset=1\" \"$grub_file\"; then sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 randomize_kstack_offset=1\"/' \"$grub_file\"; fi" \
            "Параметр ядра: randomize_kstack_offset=1"
        
        apply_or_test "kernel.vsyscall_none" "grep -q 'vsyscall=none' /proc/cmdline" \
            "if ! grep -q \"vsyscall=none\" \"$grub_file\"; then sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 vsyscall=none\"/' \"$grub_file\"; fi" \
            "Параметр ядра: vsyscall=none"
        
        apply_or_test "kernel.tsx_off" "grep -q 'tsx=off' /proc/cmdline" \
            "if ! grep -q \"tsx=off\" \"$grub_file\"; then sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 tsx=off\"/' \"$grub_file\"; fi" \
            "Параметр ядра: tsx=off"
        
        apply_or_test "kernel.debugfs_off" "grep -q 'debugfs=off' /proc/cmdline" \
            "if ! grep -q \"debugfs=off\" \"$grub_file\"; then sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 debugfs=off\"/' \"$grub_file\"; fi" \
            "Параметр ядра: debugfs=off"
    fi
    
    if [[ "$MODE" == "apply" ]]; then
        update_grub_config
    fi
}

########## Запуск секций ##########
run_sections() {
    for sec in "${SECTIONS[@]}"; do
        case "$sec" in
            "2.1") section_2_1 ;;
            "2.2") section_2_2 ;;
            "2.3") section_2_3 ;;
            "2.4") section_2_4 ;;
            "2.5") section_2_5 ;;
            "2.6") section_2_6 ;;
            "kernel") configure_kernel_params ;;
            *) warning "Неизвестная секция: $sec" ;;
        esac
    done
}

########## Оценка степени риска ##########
calculate_risk_assessment() {
    local total_checks=$((CRITICAL_RISK_TOTAL + HIGH_RISK_TOTAL + MEDIUM_RISK_TOTAL + LOW_RISK_TOTAL))
    
    if [[ $total_checks -eq 0 ]]; then
        echo -e "${YELLOW}Не выполнено проверок для оценки риска${NC}"
        return
    fi
    
    echo -e "\n=== ОЦЕНКА СТЕПЕНИ РИСКА ===" | tee -a "$LOG_FILE"
    echo -e "Критический риск: $CRITICAL_RISK_SUCCESS/$CRITICAL_RISK_TOTAL" | tee -a "$LOG_FILE"
    echo -e "Высокий риск:    $HIGH_RISK_SUCCESS/$HIGH_RISK_TOTAL" | tee -a "$LOG_FILE"
    echo -e "Средний риск:    $MEDIUM_RISK_SUCCESS/$MEDIUM_RISK_TOTAL" | tee -a "$LOG_FILE"
    echo -e "Низкий риск:     $LOW_RISK_SUCCESS/$LOW_RISK_TOTAL" | tee -a "$LOG_FILE"
    
    # Расчет общего уровня риска
    local risk_score=0
    local max_score=0
    
    if [[ $CRITICAL_RISK_TOTAL -gt 0 ]]; then
        risk_score=$((risk_score + (CRITICAL_RISK_SUCCESS * 100 / CRITICAL_RISK_TOTAL) * 4))
        max_score=$((max_score + 400))
    fi
    
    if [[ $HIGH_RISK_TOTAL -gt 0 ]]; then
        risk_score=$((risk_score + (HIGH_RISK_SUCCESS * 100 / HIGH_RISK_TOTAL) * 3))
        max_score=$((max_score + 300))
    fi
    
    if [[ $MEDIUM_RISK_TOTAL -gt 0 ]]; then
        risk_score=$((risk_score + (MEDIUM_RISK_SUCCESS * 100 / MEDIUM_RISK_TOTAL) * 2))
        max_score=$((max_score + 200))
    fi
    
    if [[ $LOW_RISK_TOTAL -gt 0 ]]; then
        risk_score=$((risk_score + (LOW_RISK_SUCCESS * 100 / LOW_RISK_TOTAL) * 1))
        max_score=$((max_score + 100))
    fi
    
    if [[ $max_score -gt 0 ]]; then
        local overall_risk_percent=$((risk_score * 100 / max_score))
        local risk_level=""
        local risk_color=""
        
        if [[ $overall_risk_percent -ge 90 ]]; then
            risk_level="НИЗКИЙ"
            risk_color=$GREEN
        elif [[ $overall_risk_percent -ge 70 ]]; then
            risk_level="СРЕДНИЙ"
            risk_color=$YELLOW
        elif [[ $overall_risk_percent -ge 50 ]]; then
            risk_level="ВЫСОКИЙ"
            risk_color=$RED
        else
            risk_level="КРИТИЧЕСКИЙ"
            risk_color=$RED
        fi
        
        echo -e "Общий уровень риска: ${risk_color}$risk_level${NC} ($overall_risk_percent%)" | tee -a "$LOG_FILE"
        
        # Рекомендации
        echo -e "\n=== РЕКОМЕНДАЦИИ ===" | tee -a "$LOG_FILE"
        if [[ $CRITICAL_RISK_SUCCESS -lt $CRITICAL_RISK_TOTAL ]]; then
            echo -e "${RED}● Критически важно устранить все уязвимости критического риска${NC}" | tee -a "$LOG_FILE"
        fi
        if [[ $HIGH_RISK_SUCCESS -lt $HIGH_RISK_TOTAL ]]; then
            echo -e "${RED}● Высокий приоритет: устранить уязвимости высокого риска${NC}" | tee -a "$LOG_FILE"
        fi
        if [[ $MEDIUM_RISK_SUCCESS -lt $MEDIUM_RISK_TOTAL ]]; then
            echo -e "${YELLOW}● Рекомендуется устранить уязвимости среднего риска${NC}" | tee -a "$LOG_FILE"
        fi
        if [[ $LOW_RISK_SUCCESS -lt $LOW_RISK_TOTAL ]]; then
            echo -e "${BLUE}● Рассмотрите устранение уязвимостей низкого риска${NC}" | tee -a "$LOG_FILE"
        fi
        
        if [[ $overall_risk_percent -ge 90 ]]; then
            echo -e "${GREEN}● Система хорошо защищена от основных угроз${NC}" | tee -a "$LOG_FILE"
        fi
    fi
}

########## Основная программа ##########
main() {
    # Проверка прав root для режима apply
    if [[ "$MODE" == "apply" ]] && [[ $EUID -ne 0 ]]; then
        error "Скрипт должен запускаться с правами root для применения настроек"
        exit 1
    fi

    log "Запуск hardening для $OS_TYPE $OS_ID $OS_VERSION"
    log "Режим: $MODE"
    log "Влияние на ОС: $OS_IMPACT_LEVEL"
    log "Уровень риска: $RISK_LEVEL"
    [[ $VERBOSE -eq 1 ]] && log "Включен подробный вывод команд"
    log "Выбранные секции: ${SECTIONS[*]}"
    log "Лог файл: $LOG_FILE"

    # Создание sysctl файла один раз
    if [[ "$MODE" == "apply" ]]; then
        create_backup
        echo "# FSTEC Security Settings" > "/etc/sysctl.d/99-fstec-security.conf"
    fi

    run_sections

    # Финальное применение sysctl
    if [[ "$MODE" == "apply" ]] && [[ -f "/etc/sysctl.d/99-fstec-security.conf" ]]; then
        safe_exec "sysctl -p /etc/sysctl.d/99-fstec-security.conf" "Применение sysctl настроек"
    fi

    # Итоговая статистика
    if [[ "$MODE" == "test" ]]; then
        if [[ $TOTAL_CHECKS -gt 0 ]]; then
            PERCENT=$(( SUCCESS_CHECKS * 100 / TOTAL_CHECKS ))
            log "Итог: $SUCCESS_CHECKS из $TOTAL_CHECKS пунктов соответствуют рекомендациям ФСТЭК"
            
            # Оценка степени риска
            calculate_risk_assessment
            
            if [[ $PERCENT -ge 80 ]]; then
                echo -e "${GREEN}Общее соответствие: $PERCENT%${NC}"
            elif [[ $PERCENT -ge 50 ]]; then
                echo -e "${YELLOW}Общее соответствие: $PERCENT%${NC}"
            else
                echo -e "${RED}Общее соответствие: $PERCENT%${NC}"
            fi
        else
            warning "Не выполнено ни одной проверки"
        fi
    else
        if [[ $ERROR_CHECKS -eq 0 ]]; then
            success "Завершено успешно! Режим: $MODE"
        else
            error "Завершено с $ERROR_CHECKS ошибками! Режим: $MODE"
        fi
        warning "Требуется перезагрузка для применения всех изменений!"
    fi
    
    exit $ERROR_CHECKS
}

########## Аргументы командной строки ##########
parse_arguments() {
    for arg in "$@"; do
        case "$arg" in
            "--test"|"-t") MODE="test" ;;
            "--apply"|"-a") MODE="apply" ;;
            "--verbose"|"-v") VERBOSE=1 ;;
            --os-impact=*)
                val="${arg#*=}"
                OS_IMPACT_LEVEL="$val"
                ;;
            --risk-level=*)
                val="${arg#*=}"
                RISK_LEVEL="$val"
                ;;
            --sections=*|-s=*)
                val="${arg#*=}"
                IFS=',' read -ra SECTIONS <<< "$val"
                ;;
            "--help"|"-h")
                echo "Использование: $0 [OPTIONS]"
                echo "  --test                 - проверка текущих настроек (по умолчанию)"
                echo "  --apply                - применение настроек (требует root)"
                echo "  --verbose              - расширенный лог (команды)"
                echo "  --os-impact=LEVEL      - влияние на ОС: all, safe, medium, dangerous"
                echo "  --risk-level=LEVEL     - уровень риска: all, low, medium, high, critical"
                echo "  --sections=SEC1,SEC2   - выбор секций (пример: --sections=2.1,2.3,kernel)"
                echo "  --help                 - справка"
                echo ""
                echo "Примеры:"
                echo "  $0 --test --os-impact=safe --risk-level=high"
                echo "  $0 --apply --sections=2.1,2.2"
                exit 0
                ;;
            *)
                error "Неизвестный аргумент: $arg"
                exit 1
                ;;
        esac
    done
}

parse_arguments "$@"
main
