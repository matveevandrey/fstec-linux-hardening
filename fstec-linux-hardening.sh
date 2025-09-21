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

# Белый список SUID/SGID программ
SUID_WHITELIST=(
    "/usr/bin/sudo"
    "/usr/bin/passwd"
    "/usr/bin/chfn"
    "/usr/bin/chsh"
    "/usr/bin/newgrp"
    "/bin/ping"
    "/bin/mount"
    "/bin/umount"
    "/bin/su"
    "/usr/bin/sudoedit"
    "/usr/bin/ssh-agent"
    "/usr/bin/expiry"
    "/usr/bin/wall"
    "/usr/bin/chage"
    "/usr/bin/gpasswd"
    "/usr/bin/crontab"
)


# Карта влияния на работу ОС для каждой настройки
declare -A OS_IMPACT_MAP=(
    ["2.1.1"]="safe"       # Запрет пустых паролей
    ["2.1.2"]="safe"       # Запрет root входа по SSH
    ["2.2.1"]="safe"       # Ограничение команды su
    ["2.2.2"]="safe"       # Настройка sudo для wheel
    ["2.3.1"]="safe"       # Права доступа к системным файлам
    ["2.3.2"]="safe"       # Права на системные директории
    ["2.3.3"]="safe"       # Права на файлы cron
    ["2.3.4"]="medium"     # Аудит SUID/SGID приложений
    ["2.3.5"]="safe"       # Права на скрытые файлы в home
    ["2.3.6"]="safe"       # Права на домашние директории
    ["2.3.7"]="safe"       # Права на rc.local/rc.d/systemd
    ["2.3.8"]="safe"       # Ограничение at
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
    ["2.3.4"]="high"       # Высокий риск при незакрытии
    ["2.3.5"]="low"        # Низкий риск при незакрытии
    ["2.3.6"]="medium"     # Средний риск при незакрытии
    ["2.3.7"]="low"        # Низкий риск при незакрытии
    ["2.3.8"]="medium"     # Средний риск при незакрытии
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
    elif [[ -f /etc/altlinux-release ]]; then
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

should_apply_risk() {
    local risk_level="$1"
    case "$RISK_LEVEL" in
        "all") return 0 ;;
        "low")     [[ "$risk_level" == "low" ]] && return 0 ;;
        "medium")  [[ "$risk_level" == "medium" ]] && return 0 ;;
        "high")    [[ "$risk_level" == "high" ]] && return 0 ;;
        "critical")[[ "$risk_level" == "critical" ]] && return 0 ;;
    esac
    return 1
}

# Функция-реализация фикса SUID/SGID (чтобы не выполнять eval)
__fix_suid_sgid() {
    find / -xdev -type f -perm /6000 2>/dev/null | while IFS= read -r f; do
        local match=0
        for w in "${SUID_WHITELIST[@]}"; do
            [[ "$f" == "$w" ]] && { match=1; break; }
        done
        if [[ $match -eq 0 ]]; then
            if [[ "$(stat -c '%U' "$f" 2>/dev/null)" != "root" ]]; then
                chmod u-s,g-s "$f" 2>/dev/null || true
                chown root:root "$f" 2>/dev/null || true
            fi
        fi
    done
}

# Функции для работы с сервисами
restart_service() {
    local service="$1"
    if [[ "$OS_TYPE" == "alt" ]]; then
        /sbin/service "$service" restart >> "$LOG_FILE" 2>&1
    elif [[ "$OS_TYPE" == "debian" ]] && [[ "$service" == "sshd" ]]; then
        # Для Debian/Ubuntu сервис SSH называется 'ssh', а не 'sshd'
        systemctl restart "ssh" >> "$LOG_FILE" 2>&1
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

# Идемпотентная запись в sysctl
set_sysctl_kv() {
    local file="$1" key="$2" val="$3"
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null; then
        sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$file"
    else
        echo "${key} = ${val}" >> "$file"
    fi
}

# Безопасное добавление параметров ядра
ensure_kernel_param() {
    local file="$1" param="$2"
    
    # Убедимся, что GRUB_CMDLINE_LINUX существует
    grep -qE '^GRUB_CMDLINE_LINUX=' "$file" || echo 'GRUB_CMDLINE_LINUX=""' >> "$file"
    
    # Обрабатываем оба возможных ключа
    for key in GRUB_CMDLINE_LINUX GRUB_CMDLINE_LINUX_DEFAULT; do
        if grep -q "^${key}=" "$file"; then
            if ! grep -q "$param" "$file"; then
                sed -i "s/^\(${key}=\"[^\"]*\)\"/\1 ${param}\"/" "$file"
            fi
        fi
    done
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
        
        # Проверяем, является ли apply_cmd функцией
        if declare -F "$apply_cmd" >/dev/null 2>&1; then
            # Это функция - вызываем напрямую
            if "$apply_cmd" >>"$LOG_FILE" 2>&1; then
                success "Применено: $desc"
                return 0
            else
                error "Ошибка применения: $desc"
                ERROR_CHECKS=$((ERROR_CHECKS+1))
                return 1
            fi
        else
            # Это команда - выполняем через eval
            if eval "$apply_cmd" >>"$LOG_FILE" 2>&1; then
                success "Применено: $desc"
                return 0
            else
                error "Ошибка применения: $desc"
                ERROR_CHECKS=$((ERROR_CHECKS+1))
                return 1
            fi
        fi
    fi
}

# Безопасное выполнение команд
safe_exec() {
    local cmd="$1"
    local desc="$2"
    
    # Проверяем, является ли cmd функцией
    if declare -F "$cmd" >/dev/null 2>&1; then
        if "$cmd" >>"$LOG_FILE" 2>&1; then
            log "Выполнено: $desc"
            return 0
        else
            error "Ошибка выполнения: $desc"
            ERROR_CHECKS=$((ERROR_CHECKS+1))
            return 1
        fi
    else
        if eval "$cmd" >>"$LOG_FILE" 2>&1; then
            log "Выполнено: $desc"
            return 0
        else
            error "Ошибка выполнения: $desc"
            ERROR_CHECKS=$((ERROR_CHECKS+1))
            return 1
        fi
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
    
    # 2.3.1 - Права доступа к системным файлам
    apply_or_test "2.3.1" \
        "[[ \$(stat -c '%a' /etc/passwd 2>/dev/null) == 644 ]] && [[ \$(stat -c '%a' /etc/group 2>/dev/null) == 644 ]] && [[ \$(stat -c '%a' /etc/shadow 2>/dev/null) =~ ^(0|640)$ ]]" \
        "chmod 644 /etc/passwd /etc/group 2>/dev/null || true; chmod 640 /etc/shadow 2>/dev/null || true; chown root:root /etc/passwd /etc/group /etc/shadow 2>/dev/null || true" \
        "Права доступа к /etc/passwd, /etc/group, /etc/shadow"
    
    # 2.3.2 - Права на системные директории
    apply_or_test "2.3.2" \
        "[[ \$(stat -c '%a' /etc 2>/dev/null) == 755 ]] && [[ \$(stat -c '%a' /bin 2>/dev/null) == 755 ]] && [[ \$(stat -c '%a' /sbin 2>/dev/null) == 755 ]] && [[ \$(stat -c '%a' /usr/bin 2>/dev/null) == 755 ]]" \
        "chmod 755 /etc /bin /sbin /usr/bin 2>/dev/null || true; chown root:root /etc /bin /sbin /usr/bin 2>/dev/null || true" \
        "Права на системные директории"
    
    # 2.3.3 - Права на файлы cron
    apply_or_test "2.3.3" \
        "! find /etc/cron* /var/spool/cron -type f -executable ! -user root 2>/dev/null | head -5 | grep -q ." \
        "find /etc/cron* /var/spool/cron -type f -executable ! -user root -exec chmod go-w {} \\; 2>/dev/null || true" \
        "Права на файлы cron"

    # 2.3.4 - Аудит SUID/SGID приложений
    apply_or_test "2.3.4" \
    "! find / -xdev -type f -perm /6000 2>/dev/null | while read -r f; do \
        if ! printf '%s\n' \"${SUID_WHITELIST[@]}\" | grep -Fxq \"\$f\"; then \
            if [[ \$(stat -c '%U' \"\$f\" 2>/dev/null) != \"root\" ]]; then \
                exit 1; \
            fi; \
        fi; \
    done; true" \
    "__fix_suid_sgid" \
    "Аудит SUID/SGID приложений"
    
    # 2.3.5 - Права на скрытые файлы в home
    apply_or_test "2.3.5" \
        "! find /home -name '.bash_history' -o -name '.history' -o -name '.sh_history' -o -name '.bashrc' -o -name '.profile' -o -name '.rhosts' ! -perm 600 2>/dev/null | head -5 | grep -q ." \
        "find /home -name '.bash_history' -o -name '.history' -o -name '.sh_history' -o -name '.bashrc' -o -name '.profile' -o -name '.rhosts' -exec chmod go-rwx {} \\; 2>/dev/null || true" \
        "Права на скрытые файлы в home"
    
    # 2.3.6 - Права на домашние директории
    apply_or_test "2.3.6" \
        "! find /home -maxdepth 1 -type d ! -perm 700 ! -user root 2>/dev/null | head -5 | grep -q ." \
        "find /home -maxdepth 1 -type d ! -perm 700 ! -user root -exec chmod 700 {} \\; 2>/dev/null || true" \
        "Права на домашние директории"
    
    # 2.3.7 - Права на rc.local/rc.d/systemd
    apply_or_test "2.3.7" \
        "! { [[ -f /etc/rc.local ]] && [[ \$(stat -c '%a' /etc/rc.local 2>/dev/null) != 744 ]]; } && \
         ! find /etc/rc*.d -type f -perm /022 2>/dev/null | head -5 | grep -q . && \
         ! find /etc/systemd/system -type f -perm /022 2>/dev/null | head -5 | grep -q ." \
        "chmod 744 /etc/rc.local 2>/dev/null || true; \
         chmod -R go-w /etc/rc*.d 2>/dev/null || true; \
         find /etc/systemd/system -type f -exec chmod go-w {} \\; 2>/dev/null || true" \
        "Права на rc.local/rc*.d и systemd unit-файлы"
    
    # 2.3.8 - Ограничение at
    apply_or_test "2.3.8" \
        "! command -v at >/dev/null || { [[ -d /var/spool/at ]] && [[ \$(stat -c '%a' /var/spool/at 2>/dev/null) -le 700 ]]; }" \
        "if command -v at >/dev/null; then \
             chmod 700 /var/spool/at 2>/dev/null || true; \
             chown root:root /var/spool/at 2>/dev/null || true; \
             echo '*' > /etc/at.deny 2>/dev/null || true; \
         fi" \
        "Ограничение at (права и deny)"
}

########## 2.4. Защита ядра ##########
section_2_4() {
    log "=== Секция 2.4: Усиление ядра ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    apply_or_test "2.4.1" "[[ \$(sysctl -n kernel.dmesg_restrict 2>/dev/null) == 1 ]]" \
        "set_sysctl_kv '$sysctl_file' 'kernel.dmesg_restrict' '1'" \
        "kernel.dmesg_restrict = 1"
    
    apply_or_test "2.4.2" "[[ \$(sysctl -n kernel.kptr_restrict 2>/dev/null) == 2 ]]" \
        "set_sysctl_kv '$sysctl_file' 'kernel.kptr_restrict' '2'" \
        "kernel.kptr_restrict = 2"
    
    apply_or_test "2.4.3" "[[ \$(sysctl -n net.core.bpf_jit_harden 2>/dev/null) == 2 ]]" \
        "set_sysctl_kv '$sysctl_file' 'net.core.bpf_jit_harden' '2'" \
        "net.core.bpf_jit_harden = 2"
}

########## 2.5. Уменьшение периметра атаки ##########
section_2_5() {
    log "=== Секция 2.5: Уменьшение периметра атаки ядра ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    apply_or_test "2.5.1" "[[ \$(sysctl -n kernel.perf_event_paranoid 2>/dev/null) == 3 ]]" \
        "set_sysctl_kv '$sysctl_file' 'kernel.perf_event_paranoid' '3'" \
        "kernel.perf_event_paranoid = 3"

    apply_or_test "2.5.2" "[[ \$(sysctl -n kernel.kexec_load_disabled 2>/dev/null) == 1 ]]" \
        "set_sysctl_kv '$sysctl_file' 'kernel.kexec_load_disabled' '1'" \
        "kernel.kexec_load_disabled = 1"
    
    apply_or_test "2.5.3" "[[ \$(sysctl -n user.max_user_namespaces 2>/dev/null) == 0 ]]" \
        "set_sysctl_kv '$sysctl_file' 'user.max_user_namespaces' '0'" \
        "user.max_user_namespaces = 0"
    
    apply_or_test "2.5.4" "[[ \$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null) == 1 ]]" \
        "set_sysctl_kv '$sysctl_file' 'kernel.unprivileged_bpf_disabled' '1'" \
        "kernel.unprivileged_bpf_disabled = 1"
    
    apply_or_test "2.5.5" "[[ \$(sysctl -n vm.unprivileged_userfaultfd 2>/dev/null) == 0 ]]" \
        "set_sysctl_kv '$sysctl_file' 'vm.unprivileged_userfaultfd' '0'" \
        "vm.unprivileged_userfaultfd = 0"
    
    apply_or_test "2.5.6" "[[ \$(sysctl -n dev.tty.ldisc_autoload 2>/dev/null) == 0 ]]" \
        "set_sysctl_kv '$sysctl_file' 'dev.tty.ldisc_autoload' '0'" \
        "dev.tty.ldisc_autoload = 0"
    
    apply_or_test "2.5.7" "[[ \$(sysctl -n vm.mmap_min_addr 2>/dev/null) -ge 4096 ]]" \
        "set_sysctl_kv '$sysctl_file' 'vm.mmap_min_addr' '65536'" \
        "vm.mmap_min_addr >= 4096"
    
    apply_or_test "2.5.8" "[[ \$(sysctl -n kernel.randomize_va_space 2>/dev/null) == 2 ]]" \
        "set_sysctl_kv '$sysctl_file' 'kernel.randomize_va_space' '2'" \
        "kernel.randomize_va_space = 2"
}

########## 2.6. Пользовательское пространство ##########
section_2_6() {
    log "=== Секция 2.6: Пользовательское пространство ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    apply_or_test "2.6.1" "[[ \$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null) == 3 ]]" \
        "set_sysctl_kv '$sysctl_file' 'kernel.yama.ptrace_scope' '3'" \
        "kernel.yama.ptrace_scope = 3"
    
    apply_or_test "2.6.2" "[[ \$(sysctl -n fs.protected_symlinks 2>/dev/null) == 1 ]]" \
        "set_sysctl_kv '$sysctl_file' 'fs.protected_symlinks' '1'" \
        "fs.protected_symlinks = 1"
    
    apply_or_test "2.6.3" "[[ \$(sysctl -n fs.protected_hardlinks 2>/dev/null) == 1 ]]" \
        "set_sysctl_kv '$sysctl_file' 'fs.protected_hardlinks' '1'" \
        "fs.protected_hardlinks = 1"
    
    apply_or_test "2.6.4" "[[ \$(sysctl -n fs.protected_fifos 2>/dev/null) == 2 ]]" \
        "set_sysctl_kv '$sysctl_file' 'fs.protected_fifos' '2'" \
        "fs.protected_fifos = 2"
    
    apply_or_test "2.6.5" "[[ \$(sysctl -n fs.protected_regular 2>/dev/null) == 2 ]]" \
        "set_sysctl_kv '$sysctl_file' 'fs.protected_regular' '2'" \
        "fs.protected_regular = 2"
    
    apply_or_test "2.6.6" "[[ \$(sysctl -n fs.suid_dumpable 2>/dev/null) == 0 ]]" \
        "set_sysctl_kv '$sysctl_file' 'fs.suid_dumpable' '0'" \
        "fs.suid_dumpable = 0"
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
        "ensure_kernel_param '$grub_file' 'init_on_alloc=1'" \
        "Параметр ядра: init_on_alloc=1"
    
    apply_or_test "kernel.slab_nomerge" "grep -q 'slab_nomerge' /proc/cmdline" \
        "ensure_kernel_param '$grub_file' 'slab_nomerge'" \
        "Параметр ядра: slab_nomerge"
    
    apply_or_test "kernel.mitigations" "grep -q 'mitigations=auto,nosmt' /proc/cmdline" \
        "ensure_kernel_param '$grub_file' 'mitigations=auto,nosmt'" \
        "Параметр ядра: mitigations=auto,nosmt"
    
    # Для не-Альт систем добавляем дополнительные параметры
    if [[ "$OS_TYPE" != "alt" ]]; then
        apply_or_test "kernel.iommu_force" "grep -q 'iommu=force' /proc/cmdline" \
            "ensure_kernel_param '$grub_file' 'iommu=force'" \
            "Параметр ядра: iommu=force"
        
        apply_or_test "kernel.iommu_strict" "grep -q 'iommu.strict=1' /proc/cmdline" \
            "ensure_kernel_param '$grub_file' 'iommu.strict=1'" \
            "Параметр ядра: iommu.strict=1"
        
        apply_or_test "kernel.iommu_passthrough" "grep -q 'iommu.passthrough=0' /proc/cmdline" \
            "ensure_kernel_param '$grub_file' 'iommu.passthrough=0'" \
            "Параметр ядра: iommu.passthrough=0"
        
        apply_or_test "kernel.randomize_kstack_offset" "grep -q 'randomize_kstack_offset=1' /proc/cmdline" \
            "ensure_kernel_param '$grub_file' 'randomize_kstack_offset=1'" \
            "Параметр ядра: randomize_kstack_offset=1"
        
        apply_or_test "kernel.vsyscall_none" "grep -q 'vsyscall=none' /proc/cmdline" \
            "ensure_kernel_param '$grub_file' 'vsyscall=none'" \
            "Параметр ядра: vsyscall=none"
        
        apply_or_test "kernel.tsx_off" "grep -q 'tsx=off' /proc/cmdline" \
            "ensure_kernel_param '$grub_file' 'tsx=off'" \
            "Параметр ядра: tsx=off"
        
        apply_or_test "kernel.debugfs_off" "grep -q 'debugfs=off' /proc/cmdline" \
            "ensure_kernel_param '$grub_file' 'debugfs=off'" \
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
        
#        if [[ $overall_risk_percent -ge 90 ]]; then
#            risk_level="НИЗКИЙ"
#            risk_color=$GREEN
#        elif [[ $overall_risk_percent -ge 70 ]]; then
#            risk_level="СРЕДНИЙ"
#            risk_color=$YELLOW
#        elif [[ $overall_risk_percent -ge 50 ]]; then
#            risk_level="ВЫСОКИЙ"
#            risk_color=$RED
#        else
#            risk_level="КРИТИЧЕСКИЙ"
#            risk_color=$RED
#        fi
        
#        echo -e "Общий уровень риска: ${risk_color}$risk_level${NC} ($overall_risk_percent%)" | tee -a "$LOG_FILE"
        
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
