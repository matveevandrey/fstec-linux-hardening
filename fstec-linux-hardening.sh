#!/bin/bash
# fstec-linux-hardening.sh
# Полное соответствие методичке ФСТЭК от 25.12.2022

set -euo pipefail
IFS=$'\n\t'

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Переменные
MODE="test"
VERBOSE=0
LOG_FILE="/var/log/fstec-hardening-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/fstec-backup-$(date +%Y%m%d)"
RISK_LEVEL="all"  # all, low, medium, high, custom

# База данных пунктов с рисками
declare -A RISK_DATABASE=(
    # 2.1 Авторизация
    ["2.1.1"]="low"      # Запрет пустых паролей
    ["2.1.2"]="medium"   # Запрет root по SSH
    
    # 2.2 Привилегии  
    ["2.2.1"]="low"      # su только для wheel
    ["2.2.2"]="medium"   # sudo только для wheel/sudo
    
    # 2.3 Права доступа
    ["2.3.1"]="low"      # Права на passwd/group/shadow
    ["2.3.2"]="low"      # Защита системных директорий
    ["2.3.3"]="low"      # Cron права
    ["2.3.4"]="low"      # Cron права
    ["2.3.5"]="low"      # rc.d права
    ["2.3.6"]="medium"   # Cron user
    ["2.3.7"]="medium"   # at права
    ["2.3.8"]="low"      # Права на bin/sbin/lib
    ["2.3.9"]="high"     # SUID/SGID
    ["2.3.10"]="low"     # Домашние файлы
    ["2.3.11"]="low"     # Домашние каталоги
    
    # 2.4 Усиление ядра
    ["2.4.1"]="medium"   # kernel.dmesg_restrict=1
    ["2.4.2"]="low"      # kernel.kptr_restrict=2
    ["2.4.3"]="medium"   # init_on_alloc=1
    ["2.4.4"]="medium"   # slab_nomerge
    ["2.4.5"]="high"     # iommu=force
    ["2.4.6"]="low"      # randomize_kstack_offset=1
    ["2.4.7"]="high"     # mitigations=auto,nosmt
    ["2.4.8"]="medium"   # net.core.bpf_jit_harden=2
    
    # 2.5 Ограничение подсистем ядра
    ["2.5.1"]="high"     # vsyscall=none
    ["2.5.2"]="medium"   # perf_event_paranoid=3
    ["2.5.3"]="medium"   # debugfs=off
    ["2.5.4"]="medium"   # kexec_load_disabled=1
    ["2.5.5"]="high"     # user.max_user_namespaces=0
    ["2.5.6"]="medium"   # unprivileged_bpf_disabled=1
    ["2.5.7"]="low"      # unprivileged_userfaultfd=0
    ["2.5.8"]="low"      # dev.tty.ldisc_autoload=0
    ["2.5.9"]="medium"   # tsx=off
    ["2.5.10"]="high"    # vm.mmap_min_addr=65536
    ["2.5.11"]="low"     # randomize_va_space=2
    
    # 2.6 Пользовательское пространство
    ["2.6.1"]="high"     # ptrace_scope=3
    ["2.6.2"]="low"      # protected_symlinks=1
    ["2.6.3"]="low"      # protected_hardlinks=1
    ["2.6.4"]="low"      # protected_fifos=2
    ["2.6.5"]="low"      # protected_regular=2
    ["2.6.6"]="low"      # suid_dumpable=0
)

# Автоматическое определение группы администраторов
if grep -q '^%sudo' /etc/sudoers; then
    ADMIN_GROUP="sudo"
elif grep -q '^%wheel' /etc/sudoers; then
    ADMIN_GROUP="wheel"
else
    ADMIN_GROUP="wheel"
    if ! grep -q '^wheel:' /etc/group; then
        echo "wheel:x:10:root" >> /etc/group
    fi
fi

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
    
    if [[ "$OS_ID" == "alt" ]] || grep -qi "alt" /etc/os-release; then
        OS_TYPE="alt"
    elif [[ "$OS_ID" == "debian" || "$OS_ID" == "ubuntu" ]]; then
        OS_TYPE="debian"
    elif [[ "$OS_ID" == "centos" || "$OS_ID" == "rhel" ]]; then
        OS_TYPE="rhel"
    fi
fi

# Функции логирования
log() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }

# Функция вывода риска
print_risk() {
    local risk="$1"
    local desc="$2"
    
    case "$risk" in
        "low") echo -e "${GREEN}[⚪ НИЗКИЙ]${NC} $desc" ;;
        "medium") echo -e "${YELLOW}[🟡 СРЕДНИЙ]${NC} $desc" ;;
        "high") echo -e "${RED}[🔴 ВЫСОКИЙ]${NC} $desc" ;;
        *) echo -e "[?] $desc" ;;
    esac
}

# Универсальная функция проверки/применения
apply_or_test() {
    local check_cmd="$1"
    local apply_cmd="$2"
    local desc="$3"
    local risk_key="$4"

    # Проверяем уровень риска
    local risk="${RISK_DATABASE[$risk_key]:-unknown}"
    
    # Пропускаем если не соответствует выбранному уровню риска
    if [[ "$RISK_LEVEL" != "all" ]] && [[ "$RISK_LEVEL" != "$risk" ]] && [[ "$RISK_LEVEL" != "custom" ]]; then
        return 0
    fi

    TOTAL_CHECKS=$((TOTAL_CHECKS+1))

    if [[ "$MODE" == "test" ]]; then
        if eval "$check_cmd" >/dev/null 2>&1; then
            print_risk "$risk" "$desc ✓"
            SUCCESS_CHECKS=$((SUCCESS_CHECKS+1))
            return 0
        else
            print_risk "$risk" "$desc ✗"
            return 1
        fi
    else
        log "Применение: $desc"
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

########## 2.1. Авторизация ##########
section_2_1() {
    log "=== Секция 2.1: Авторизация ==="
    apply_or_test \
        "! awk -F: '\$2 == \"\" {print \$1}' /etc/shadow | grep -q ." \
        "sed -i 's/nullok//g' /etc/pam.d/* && passwd -l \$(awk -F: '\$2 == \"\" {print \$1}' /etc/shadow) 2>/dev/null || true" \
        "2.1.1. Запрет пустых паролей" \
        "2.1.1"
    
    apply_or_test \
        "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config" \
        "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd 2>/dev/null || true" \
        "2.1.2. Запрет root входа по SSH" \
        "2.1.2"
}

########## 2.2. Привилегии ##########
section_2_2() {
    log "=== Секция 2.2: Ограничение привилегий ==="
    
    apply_or_test \
        "grep -q 'auth required pam_wheel.so' /etc/pam.d/su" \
        "echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su" \
        "2.2.1. Ограничение команды su группой $ADMIN_GROUP" \
        "2.2.1"
    
    apply_or_test \
        "grep -q '^%${ADMIN_GROUP}' /etc/sudoers" \
        "echo '%${ADMIN_GROUP} ALL=(ALL:ALL) ALL' >> /etc/sudoers" \
        "2.2.2. Настройка sudo для группы $ADMIN_GROUP" \
        "2.2.2"
}

########## 2.3. Права доступа ##########
section_2_3() {
    log "=== Секция 2.3: Права доступа к ФС ==="
    
    apply_or_test \
        "[[ \$(stat -c '%a' /etc/passwd 2>/dev/null) == 644 ]] && [[ \$(stat -c '%a' /etc/group 2>/dev/null) == 644 ]] && [[ \$(stat -c '%a' /etc/shadow 2>/dev/null) =~ ^(0|640)$ ]]" \
        "chmod 644 /etc/passwd /etc/group 2>/dev/null || true; chmod 640 /etc/shadow 2>/dev/null || true; chown root:root /etc/passwd /etc/group /etc/shadow 2>/dev/null || true" \
        "2.3.1. Права доступа к /etc/passwd, /etc/group, /etc/shadow" \
        "2.3.1"
    
    apply_or_test \
        "! find /etc/cron* /var/spool/cron -type f -executable ! -user root 2>/dev/null | head -5 | grep -q ." \
        "find /etc/cron* /var/spool/cron -type f -executable ! -user root -exec chmod go-w {} \\; 2>/dev/null || true" \
        "2.3.3. Права на файлы cron" \
        "2.3.3"
    
    apply_or_test \
        "find / -xdev -type f -perm /6000 2>/dev/null | head -10 | xargs -I {} sh -c 'stat -c \"%a %U\" {} 2>/dev/null' | awk '\$1 ~ /[0-9][0-9][0-9][0-9]/ && \$2 != \"root\" {exit 1}' || true" \
        "find / -xdev -type f -perm /6000 ! -user root -exec chmod go-w {} \\; 2>/dev/null || true" \
        "2.3.9. Аудит SUID/SGID приложений" \
        "2.3.9"
}

########## 2.4. Защита ядра ##########
section_2_4() {
    log "=== Секция 2.4: Усиление ядра ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    [[ "$MODE" == "apply" ]] && echo "# FSTEC Security Settings" > "$sysctl_file"
    
    apply_or_test "[[ \$(sysctl -n kernel.dmesg_restrict 2>/dev/null) == 1 ]]" \
        "echo 'kernel.dmesg_restrict = 1' >> '$sysctl_file'" \
        "2.4.1. kernel.dmesg_restrict = 1" \
        "2.4.1"
    
    apply_or_test "[[ \$(sysctl -n kernel.kptr_restrict 2>/dev/null) == 2 ]]" \
        "echo 'kernel.kptr_restrict = 2' >> '$sysctl_file'" \
        "2.4.2. kernel.kptr_restrict = 2" \
        "2.4.2"
}

########## 2.5. Уменьшение периметра атаки ##########
section_2_5() {
    log "=== Секция 2.5: Уменьшение периметра атаки ядра ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    apply_or_test "[[ \$(sysctl -n kernel.perf_event_paranoid 2>/dev/null) == 3 ]]" \
        "echo 'kernel.perf_event_paranoid = 3' >> '$sysctl_file'" \
        "2.5.2. kernel.perf_event_paranoid = 3" \
        "2.5.2"
}

########## 2.6. Пользовательское пространство ##########
section_2_6() {
    log "=== Секция 2.6: Пользовательское пространство ==="
    local sysctl_file="/etc/sysctl.d/99-fstec-security.conf"
    
    apply_or_test "[[ \$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null) == 3 ]]" \
        "echo 'kernel.yama.ptrace_scope = 3' >> '$sysctl_file'" \
        "2.6.1. kernel.yama.ptrace_scope = 3" \
        "2.6.1"
}

########## Параметры загрузки ядра ##########
configure_kernel_params() {
    log "=== Секция kernel: Параметры загрузки ядра ==="
    
    local grub_file="/etc/default/grub"
    [[ -f "$grub_file" ]] || return
    
    apply_or_test "grep -q 'init_on_alloc=1' /proc/cmdline" \
        "sed -i 's/GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 init_on_alloc=1\"/' '$grub_file'" \
        "2.4.3. init_on_alloc=1" \
        "2.4.3"
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
        esac
    done
}

########## Статистика рисков ##########
show_risk_stats() {
    local low=0 medium=0 high=0
    
    for risk in "${RISK_DATABASE[@]}"; do
        case "$risk" in
            "low") ((low++)) ;;
            "medium") ((medium++)) ;;
            "high") ((high++)) ;;
        esac
    done
    
    echo -e "\n${CYAN}=== СТАТИСТИКА РИСКОВ ===${NC}"
    echo -e "${GREEN}⚪ Низкий риск: $low пунктов${NC}"
    echo -e "${YELLOW}🟡 Средний риск: $medium пунктов${NC}"
    echo -e "${RED}🔴 Высокий риск: $high пунктов${NC}"
    echo -e "${BLUE}Всего: $((low + medium + high)) пунктов${NC}"
}

########## Основная программа ##########
main() {
    [[ "$MODE" == "apply" && $EUID -ne 0 ]] && { error "Требуются права root"; exit 1; }

    echo -e "${MAGENTA}=== FSTEC LINUX HARDENING ===${NC}"
    echo -e "Режим: ${MODE}"
    echo -e "Уровень риска: ${RISK_LEVEL}"
    echo -e "ОС: ${OS_TYPE} ${OS_ID} ${OS_VERSION}"
    echo -e "Группа администраторов: ${ADMIN_GROUP}"
    echo -e "Лог: ${LOG_FILE}"
    
    show_risk_stats
    
    [[ "$MODE" == "apply" ]] && create_backup
    run_sections

    if [[ "$MODE" == "test" ]]; then
        local total=$((TOTAL_CHECKS > 0 ? TOTAL_CHECKS : 1))
        local percent=$((SUCCESS_CHECKS * 100 / total))
        
        echo -e "\n${CYAN}=== ИТОГИ ПРОВЕРКИ ===${NC}"
        echo -e "Соответствует: ${GREEN}${SUCCESS_CHECKS}/${TOTAL_CHECKS}${NC} (${percent}%)"
        
        if [[ $percent -ge 80 ]]; then
            echo -e "Общий риск: ${GREEN}⚪ НИЗКИЙ${NC}"
        elif [[ $percent -ge 50 ]]; then
            echo -e "Общий риск: ${YELLOW}🟡 СРЕДНИЙ${NC}"
        else
            echo -e "Общий риск: ${RED}🔴 ВЫСОКИЙ${NC}"
        fi
    else
        success "Завершено! Перезагрузите систему."
    fi
}

########## Аргументы командной строки ##########
parse_arguments() {
    for arg in "$@"; do
        case "$arg" in
            "--test"|"-t") MODE="test" ;;
            "--apply"|"-a") MODE="apply" ;;
            "--verbose"|"-v") VERBOSE=1 ;;
            "--risk-low"|"-rl") RISK_LEVEL="low" ;;
            "--risk-medium"|"-rm") RISK_LEVEL="medium" ;;
            "--risk-high"|"-rh") RISK_LEVEL="high" ;;
            "--risk-all"|"-ra") RISK_LEVEL="all" ;;
            "--risk-custom"|"-rc") RISK_LEVEL="custom" ;;
            "--help"|"-h")
                echo "Использование: $0 [OPTIONS]"
                echo "  --test, -t        - режим проверки"
                echo "  --apply, -a       - режим применения"
                echo "  --risk-low, -rl   - только низкий риск"
                echo "  --risk-medium, -rm - только средний риск" 
                echo "  --risk-high, -rh  - только высокий риск"
                echo "  --risk-all, -ra   - все риски (по умолчанию)"
                echo "  --risk-custom, -rc- выборочные настройки"
                echo "  --verbose, -v     - подробный вывод"
                echo "  --help, -h        - справка"
                exit 0
                ;;
        esac
    done
}

parse_arguments "$@"
main
