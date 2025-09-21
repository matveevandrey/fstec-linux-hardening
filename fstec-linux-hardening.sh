rdgw\CourseAL-1805
I4r[vI[^Z>tG1h8cYvuZfJdwpjz8wDiSKmJdqeT}@w@

sa
password


Перезапуск SSH на Debian/Ubuntu

Сейчас вызывается restart_service sshd, а в Debian сервис называется ssh, и это даст «ошибку применения» (хотя конфиг поменяется).
Как поправить функцию restart_service:


2.3.3: фиксация SUID/SGID сейчас не исправляет проблему
Тест ищет файлы -perm /6000 и «не root» — но в применении делается лишь chmod go-w. Это не убирает ни SUID/SGID, ни меняет владельца.
Минимально безопасная правка (с whitelist):
# Белый список SUID/SGID (пример; дополни под свою систему)
SUID_WHITELIST="/usr/bin/sudo /usr/bin/passwd /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /bin/ping /bin/mount /bin/umount"


2.3.2: название vs фактическая проверка

В OS_IMPACT_MAP «2.3.2 = Права на файлы cron», но по методичке 2.3.2 — про системные директории. Либо переименуй чек-ID, либо добавь реальную проверку системных путей:
А проверку cron-файлов выдели отдельным номером (2.3.3/2.3.4 по твоей внутренней нумерации или уточни маппинг).

2.3.5 и 2.3.7 ещё полезно добить до идеала
rc.local / rc.d / systemd-юниты* (на новых системах почти не используются, но проверяющие любят этот пункт):

apply_or_test "2.3.5-rc" \
  "! { [[ -f /etc/rc.local ]] && [[ $(stat -c '%a' /etc/rc.local) != 744 ]]; } && \
   ! find /etc/rc*.d -type f -perm /022 2>/dev/null | grep -q '.' && \
   ! find /etc/systemd/system -type f -perm /022 2>/dev/null | grep -q '.'" \
  "chmod 744 /etc/rc.local 2>/dev/null || true; chmod -R go-w /etc/rc*.d 2>/dev/null || true; find /etc/systemd/system -type f -exec chmod go-w {} \; 2>/dev/null || true" \
  "Права на rc.local/rc*.d и systemd unit-файлы"


at (если установлен):

apply_or_test "2.3.7" \
  "! command -v at >/dev/null || { [[ -d /var/spool/at ]] && [[ $(stat -c '%a' /var/spool/at) -le 700 ]]; }" \
  "if command -v at >/dev/null; then \
     chmod 700 /var/spool/at 2>/dev/null || true; chown root:root /var/spool/at 2>/dev/null || true; \
     echo '*' > /etc/at.deny 2>/dev/null || true; \
   fi" \
  "Ограничение at (права и deny)"



Idempotent-запись в /etc/sysctl.d/99-fstec-security.conf

Сейчас строки просто дописываются — при повторных запусках будут дубликаты. Введи вспомогательную функцию:

set_sysctl_kv() {
  local file="$1" key="$2" val="$3"
  grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null \
    && sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$file" \
    || echo "${key} = ${val}" >> "$file"
}
# Использование: set_sysctl_kv "$sysctl_file" "kernel.kptr_restrict" "2"


(и заменить в секциях echo 'k=v' >> на set_sysctl_kv).

Добавить «безопасный» апдейтер GRUB-параметров

Sed, который меняет только GRUB_CMDLINE_LINUX="...", не всегда работает (у многих значения живут в GRUB_CMDLINE_LINUX_DEFAULT). Сделай обёртку:

ensure_kernel_param() {
  local file="$1" param="$2"
  grep -qE '^GRUB_CMDLINE_LINUX=' "$file" || echo 'GRUB_CMDLINE_LINUX=""' >> "$file"
  for key in GRUB_CMDLINE_LINUX GRUB_CMDLINE_LINUX_DEFAULT; do
    if grep -q "^${key}=" "$file"; then
      grep -q "$param" "$file" || sed -i "s/^\(${key}=\"[^\"]*\)\"/\1 ${param}\"/" "$file"
    fi
  done
}
# Пример: ensure_kernel_param "$grub_file" "slab_nomerge"
