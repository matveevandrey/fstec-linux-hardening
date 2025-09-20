# FSTEC Linux Hardening

Скрипт для применения рекомендаций ФСТЭК РФ по безопасной настройке Linux (от 25.12.2022). Поддержка: **Debian 12**, Ubuntu 20.04+, RHEL 8+, Astra Linux, ALT СП 10.

> ⚠️ Параметры ядра применяются через GRUB и требуют перезагрузки.
> Режим по умолчанию — `test` (ничего не меняет).

---

## Быстрый старт

```bash
# тест без изменений
./fstec-linux-hardening.sh
./fstec-linux-hardening.sh --test

# применить (требуется root)
sudo ./fstec-linux-hardening.sh --apply

# подробный лог выполняемых команд
./fstec-linux-hardening.sh --verbose

# выбрать секции (через запятую)
./fstec-linux-hardening.sh --sections=2.1,2.3
./fstec-linux-hardening.sh --sections=kernel

# отфильтровать меры по влиянию на ОС:
#   all | safe | medium | dangerous
./fstec-linux-hardening.sh --os-impact=safe

# отфильтровать по уровню риска:
#   all | low | medium | high | critical
./fstec-linux-hardening.sh --risk-level=high

```

|          № | Мера                                    | Как закрывается                                                            | Риск незакрытия | Влияние на ОС                 |
| ---------: | --------------------------------------- | -------------------------------------------------------------------------- | --------------- | ----------------------------- |
|  **2.1.1** | Запрет пустых паролей                   | Удаление `nullok` из PAM; блокировка пустых учёток                         | 🟥              | ⚪                             |
|  **2.1.2** | Запрет root-входа по SSH                | `PermitRootLogin no`                                                       | 🟥              | 🟡                            |
|  **2.2.1** | su только для admin-группы              | `pam_wheel.so` (или `group=sudo`)                                          | 🟡              | ⚪                             |
|  **2.2.2** | sudo только для admin-группы            | `%wheel` или `%sudo` в sudoers                                             | 🟡              | 🟡                            |
|  **2.3.1** | Права на `passwd/group/shadow`          | `644/644/640`, `root:root`                                                 | 🟥              | ⚪                             |
|  **2.3.2** | Защита системных директорий             | `chmod 755`, `chown root:root` на ключевые каталоги                        | 🔴              | ⚪                             |
|  **2.3.3** | Cron файлы/каталоги                     | `chown root`, `chmod 600/700`, `chown root:crontab` для спула              | 🟡              | 🟡                            |
|  **2.3.4** | Аудит/фикс SUID/SGID                    | `find -perm /6000`, whitelist, `chmod u-s,g-s`, `chown root:root`          | 🟥              | 🔴                            |
|  **2.3.5** | Dotfiles в \$HOME                       | `chmod 600` на `.bashrc/.profile/.rhosts/*.history`                        | 🟢              | ⚪                             |
|  **2.3.6** | Домашние каталоги                       | `chmod 700` на `/home/*` (кроме root)                                      | 🟡              | ⚪                             |
|  **2.3.7** | Автозагрузка (rc/systemd)               | `chmod 744 /etc/rc.local`, `chmod -R go-w /etc/rc*.d`, права на unit-файлы | 🟡              | ⚪                             |
|  **2.3.8** | Ограничение at                          | `chmod 700 /var/spool/at`, `at.deny: *` (или удалить пакет)                | 🟡              | 🟡                            |
|  **2.4.1** | `kernel.dmesg_restrict=1`               | `sysctl`                                                                   | 🔴              | 🟡                            |
|  **2.4.2** | `kernel.kptr_restrict=2`                | `sysctl`                                                                   | 🔴              | ⚪                             |
|  **2.4.3** | `net.core.bpf_jit_harden=2`             | `sysctl`                                                                   | 🟡              | 🟡                            |
|  **2.4.4** | `init_on_alloc=1`                       | Параметр ядра (GRUB)                                                       | 🟡              | 🟡                            |
|  **2.4.5** | `slab_nomerge`                          | Параметр ядра (GRUB)                                                       | 🟡              | 🟡                            |
|  **2.4.6** | `randomize_kstack_offset=1`             | Параметр ядра (GRUB)                                                       | 🟢              | ⚪                             |
|  **2.4.7** | `mitigations=auto,nosmt`                | Параметр ядра (GRUB)                                                       | 🟡              | 🔴                            |
|  **2.4.8** | IOMMU защита                            | `iommu=force`, `iommu.strict=1`, `iommu.passthrough=0`                     | 🟡              | 🔴                            |
|  **2.5.1** | `vsyscall=none`                         | Параметр ядра (GRUB)                                                       | 🔴              | 🔴                            |
|  **2.5.2** | `kernel.perf_event_paranoid=3`          | `sysctl`                                                                   | 🟡              | 🟡                            |
|  **2.5.3** | `debugfs=off`                           | Параметр ядра (GRUB)                                                       | 🟢              | 🟡                            |
|  **2.5.4** | `kernel.kexec_load_disabled=1`          | `sysctl` (write-once)                                                      | 🟡              | 🟡                            |
|  **2.5.5** | `user.max_user_namespaces=0`            | `sysctl`                                                                   | 🟥              | 🔴                            |
|  **2.5.6** | `kernel.unprivileged_bpf_disabled=1`    | `sysctl`                                                                   | 🔴              | 🟡                            |
|  **2.5.7** | `vm.unprivileged_userfaultfd=0`         | `sysctl`                                                                   | 🟡              | ⚪                             |
|  **2.5.8** | `dev.tty.ldisc_autoload=0`              | `sysctl`                                                                   | 🟢              | ⚪                             |
|  **2.5.9** | `vm.mmap_min_addr ≥ 4096` (лучше 65536) | `sysctl`                                                                   | 🟡              | 🔴                            |
| **2.5.10** | `kernel.randomize_va_space=2`           | `sysctl`                                                                   | 🟥              | ⚪                             |
|  **2.6.1** | `kernel.yama.ptrace_scope=3`            | `sysctl`                                                                   | 🔴              | 🔴                            |
|  **2.6.2** | `fs.protected_symlinks=1`               | `sysctl`                                                                   | 🟡              | ⚪                             |
|  **2.6.3** | `fs.protected_hardlinks=1`              | `sysctl`                                                                   | 🟡              | ⚪                             |
|  **2.6.4** | `fs.protected_fifos=2`                  | `sysctl`                                                                   | 🟡              | ⚪ *(может не поддерживаться)* |
|  **2.6.5** | `fs.protected_regular=2`                | `sysctl`                                                                   | 🟢              | ⚪                             |
|  **2.6.6** | `fs.suid_dumpable=0`                    | `sysctl`                                                                   | 🟡              | ⚪                             |

## 📊 Сводка по мерам

### Риск незакрытия
- 🟢 **Низкий**: 4 меры  
- 🟡 **Средний**: 15 мер  
- 🔴 **Высокий**: 13 мер  
- 🟥 **Критический**: 8 мер  

### Влияние на ОС
- ⚪ **Низкое**: 19 мер  
- 🟡 **Среднее**: 14 мер  
- 🔴 **Высокое**: 7 мер  

---
