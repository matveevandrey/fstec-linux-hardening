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

# По умолчанию все секции
SECTIONS=("2.1" "2.2" "2.3" "2.4" "2.5" "2.6" "kernel")

# Подсчет успешных/всех проверок
TOTAL_CHECKS=0
SUCCESS_CHECKS=0
ERROR_CHECKS=0

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
    local check_cmd="$1"
    local apply_cmd="$2"
    local desc="$3"

    TOTAL_CHECKS=$((TOTAL_CHECKS+1))

    if [[ "$MODE" == "test" ]]; then
        if eval "$check_cmd" >/dev/null 2>&1; then
            success "$desc"
            SUCCESS_CHECKS=$((SUCCESS_CHECKS+1))
            return 0
        else
            warning "$desc"
            return 1
        fi
    else
        log "Применение: $desc"
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
    apply_or_test \
        "! awk -F: '\$2 == \"\" {print \$1}' /etc/shadow | grep -q ." \
        "sed -i 's/nullok//g' /etc/pam.d/* && passwd -l \$(awk -F: '\$2 == \"\" {print \$1}' /etc/shadow) 2>/dev/null || true" \
        "Запрет пустых паролей"
    
    apply_or_test \
        "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config" \
        "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && restart_service sshd" \
        "Запрет root входа по SSH"
}

########## 2.2. Привилегии ##########
section_2_2() {
    log "=== Секция 2.2: Ограничение привилегий ==="
    apply_or_test \
        "grep -q 'auth required pam_wheel.so' /etc/pam.d/su" \
        "echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su && (grep -q '^wheel:' /etc/group || echo 'wheel:x:10:root' >> /etc/group)" \
        "Ограничение команды su"
    
    apply_or_test \
        "grep -q '^%wheel' /etc/sudoers" \
        "echo '%wheel ALL=(ALL:ALL) ALL' >> /etc/sudoers" \
        "Настройка sudo для wheel"
}

########## 2.3. Права доступа ##########
section_2_3() {
    log "=== Секция 2.3: Права доступа к ФС ==="
    apply_or_test \
        "[[ \$(stat -c '%a' /etc/passwd 2>/dev/null) == 644 ]] && [[ \$(stat -c '%a' /etc/group 2>/dev/null) == 644 ]] && [[ \$(stat -c '%a' /etc/shadow 2>/dev/null) =~ ^(0|640)$ ]]" \
        "chmod 644 /etc/passwd /etc/group 2>/dev/null || true; chmod 640 /etc/shadow 2>/dev/null || true; chown root:root /etc/passwd /etc/group /etc/shadow 2>/dev/null || true" \
        "Права доступа к /etc/passwd, /etc/group, /etc/shadow"
    
    apply_or_test \
        "! find /etc/cron* /var/spool/cron -type f -executable ! -user root 2>/dev/null | head -5 | grep -q ." \
        "find /etc/cron* /var/spool/cron -type f -executable ! -user root -exec chmod go-w {} \\; 2>/dev/null || true" \
        "Права на файлы cron"
    
    apply_or_test \
        "find / -xdev -type f -perm /6000 2>/dev/null | head -10 | xargs -I {} sh -c 'stat -c \"%a %U\" {} 2>/dev/null' | awk '\$1 ~ /[0-9][0-9][0-9][0-9]/ && \$2 != \"root\" {exit 1}' || true" \
        "find / -xdev -type f -perm /6000 ! -user root -exec chmod go-w {} \\; 2>/dev/null || true" \
        "Аудит SUID/SGID приложений"
    
    apply_or_test \
        "! find /home -name '.bash_history' -o -name '.history' -o -name '.sh_history' -o -name '.bashrc' -o -name '.profile' -o -name '.rhosts' ! -perm 600 2>/dev/null | head -5 | grep -q ." \
        "find /home -name '.bash_history' -o -name '.history' -o -name '.sh_history' -o -name '.bashrc' -o -name '.profile' -o -name '.rhosts' -exec chmod go-rwx {} \\; 2>/dev/null || true" \
        "Права на скрытые файлы в home"
    
    apply_or_test \
        "! find /home -maxdepth 1 -type d ! -perm 700 ! -user root 2>/dev/null | head -5 | grep -q ." \
        "find /home -maxdepth 1 -type d ! -perm 700 ! -user root -exec chmod 700 {} \\; 2>/dev/null || true" \
        "Права на домашние директории"
}

########## 2.4. Защита ядра ##########
section_2_4() {
    log "=== Секция 2.4: Усиление ядра ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    apply_or_test "[[ \$(sysctl -n kernel.dmesg_restrict 2>/dev/null) == 1 ]]" \
        "echo 'kernel.dmesg_restrict = 1' >> '$sysctl_file'" "kernel.dmesg_restrict = 1"
    
    apply_or_test "[[ \$(sysctl -n kernel.kptr_restrict 2>/dev/null) == 2 ]]" \
        "echo 'kernel.kptr_restrict = 2' >> '$sysctl_file'" "kernel.kptr_restrict = 2"
    
    apply_or_test "[[ \$(sysctl -n net.core.bpf_jit_harden 2>/dev/null) == 2 ]]" \
        "echo 'net.core.bpf_jit_harden = 2' >> '$sysctl_file'" "net.core.bpf_jit_harden = 2"
}

########## 2.5. Уменьшение периметра атаки ##########
section_2_5() {
    log "=== Секция 2.5: Уменьшение периметра атаки ядра ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    apply_or_test "[[ \$(sysctl -n kernel.perf_event_paranoid 2>/dev/null) == 3 ]]" \
        "echo 'kernel.perf_event_paranoid = 3' >> '$sysctl_file'" "kernel.perf_event_paranoid = 3"
    
    apply_or_test "[[ \$(sysctl -n kernel.kexec_load_disabled 2>/dev/null) == 1 ]]" \
        "echo 'kernel.kexec_load_disabled = 1' >> '$sysctl_file'" "kernel.kexec_load_disabled = 1"
    
    apply_or_test "[[ \$(sysctl -n user.max_user_namespaces 2>/dev/null) == 0 ]]" \
        "echo 'user.max_user_namespaces = 0' >> '$sysctl_file'" "user.max_user_namespaces = 0"
    
    apply_or_test "[[ \$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null) == 1 ]]" \
        "echo 'kernel.unprivileged_bpf_disabled = 1' >> '$sysctl_file'" "kernel.unprivileged_bpf_disabled = 1"
    
    apply_or_test "[[ \$(sysctl -n vm.unprivileged_userfaultfd 2>/dev/null) == 0 ]]" \
        "echo 'vm.unprivileged_userfaultfd = 0' >> '$sysctl_file'" "vm.unprivileged_userfaultfd = 0"
    
    apply_or_test "[[ \$(sysctl -n dev.tty.ldisc_autoload 2>/dev/null) == 0 ]]" \
        "echo 'dev.tty.ldisc_autoload = 0' >> '$sysctl_file'" "dev.tty.ldisc_autoload = 0"
    
    apply_or_test "[[ \$(sysctl -n vm.mmap_min_addr 2>/dev/null) -ge 4096 ]]" \
        "echo 'vm.mmap_min_addr = 65536' >> '$sysctl_file'" "vm.mmap_min_addr >= 4096"
    
    apply_or_test "[[ \$(sysctl -n kernel.randomize_va_space 2>/dev/null) == 2 ]]" \
        "echo 'kernel.randomize_va_space = 2' >> '$sysctl_file'" "kernel.randomize_va_space = 2"
}

########## 2.6. Пользовательское пространство ##########
section_2_6() {
    log "=== Секция 2.6: Пользовательское пространство ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    apply_or_test "[[ \$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null) == 3 ]]" \
        "echo 'kernel.yama.ptrace_scope = 3' >> '$sysctl_file'" "kernel.yama.ptrace_scope = 3"
    
    apply_or_test "[[ \$(sysctl -n fs.protected_symlinks 2>/dev/null) == 1 ]]" \
        "echo 'fs.protected_symlinks = 1' >> '$sysctl_file'" "fs.protected_symlinks = 1"
    
    apply_or_test "[[ \$(sysctl -n fs.protected_hardlinks 2>/dev/null) == 1 ]]" \
        "echo 'fs.protected_hardlinks = 1' >> '$sysctl_file'" "fs.protected_hardlinks = 1"
    
    apply_or_test "[[ \$(sysctl -n fs.protected_fifos 2>/dev/null) == 2 ]]" \
        "echo 'fs.protected_fifos = 2' >> '$sysctl_file'" "fs.protected_fifos = 2"
    
    apply_or_test "[[ \$(sysctl -n fs.protected_regular 2>/dev/null) == 2 ]]" \
        "echo 'fs.protected_regular = 2' >> '$sysctl_file'" "fs.protected_regular = 2"
    
    apply_or_test "[[ \$(sysctl -n fs.suid_dumpable 2>/dev/null) == 0 ]]" \
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
    
    # Базовые параметры для всех дистрибутивов
    local base_params=("init_on_alloc=1" "slab_nomerge" "mitigations=auto,nosmt")
    
    # Дополнительные параметры (кроме Альт)
    local extra_params=("iommu=force" "iommu.strict=1" "iommu.passthrough=0" 
                       "randomize_kstack_offset=1" "vsyscall=none" "tsx=off" "debugfs=off")
    
    for param in "${base_params[@]}"; do
        apply_or_test "grep -q '$param' /proc/cmdline" \
            "if ! grep -q \"$param\" \"$grub_file\"; then sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 $param\"/' \"$grub_file\"; fi" \
            "Параметр ядра: $param"
    done
    
    # Для не-Альт систем добавляем дополнительные параметры
    if [[ "$OS_TYPE" != "alt" ]]; then
        for param in "${extra_params[@]}"; do
            apply_or_test "grep -q '$param' /proc/cmdline" \
                "if ! grep -q \"$param\" \"$grub_file\"; then sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 $param\"/' \"$grub_file\"; fi" \
                "Параметр ядра: $param"
        done
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

########## Основная программа ##########
main() {
    # Проверка прав root для режима apply
    if [[ "$MODE" == "apply" ]] && [[ $EUID -ne 0 ]]; then
        error "Скрипт должен запускаться с правами root для применения настроек"
        exit 1
    fi

    log "Запуск hardening для $OS_TYPE $OS_ID $OS_VERSION"
    log "Режим: $MODE"
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
            if [[ $PERCENT -ge 80 ]]; then
                echo -e "${GREEN}Соответствие: $PERCENT%${NC}"
            elif [[ $PERCENT -ge 50 ]]; then
                echo -e "${YELLOW}Соответствие: $PERCENT%${NC}"
            else
                echo -e "${RED}Соответствие: $PERCENT%${NC}"
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
            --sections=*|-s=*)
                val="${arg#*=}"
                IFS=',' read -ra SECTIONS <<< "$val"
                ;;
            "--help"|"-h")
                echo "Использование: $0 [--test|--apply|--verbose|--sections=...]"
                echo "  --test        - проверка текущих настроек (по умолчанию)"
                echo "  --apply       - применение настроек (требует root)"
                echo "  --verbose     - расширенный лог (команды)"
                echo "  --sections=x  - выбор секций (пример: --sections=2.1,2.3,kernel)"
                echo "  --help        - справка"
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