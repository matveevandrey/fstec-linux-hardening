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


|          № | Мера                                 | Как закрывается в скрипте                             | Риск незакрытия |             Влияние на ОС             |
| ---------: | ------------------------------------ | ----------------------------------------------------- | :-------------: | :-----------------------------------: |
|  **2.1.1** | Запрет пустых паролей                | Удаление `nullok` из PAM; блокировка пустых учёток    |        🔴       |                   ⚪                   |
|  **2.1.2** | Запрет root-входа по SSH             | `PermitRootLogin no`                                  |        🔴       |      🟡 (меняется привычный вход)     |
|  **2.2.1** | `su` только для admin-группы         | `pam_wheel.so use_uid`                                |        🟡       |                   ⚪                   |
|  **2.2.2** | `sudo` только для admin-группы       | `%wheel ALL=(ALL:ALL) ALL` (или `%sudo`)              |        🟡       |   🟡 (проверить используемую группу)  |
|  **2.3.1** | Права на `passwd/group/shadow`       | `644/644/640`, `root:root`                            |        🔴       |                   ⚪                   |
|  **2.3.2** | Защита системных директорий          | `chmod go-w` на `/bin /sbin /usr/bin /usr/sbin /lib*` |        🔴       |                   ⚪                   |
|  **2.3.3** | Аудит/фикс SUID/SGID                 | Поиск `-perm /6000`, white-list, `chmod u-s,g-s`      |        🔴       |    🔴 (может сломать часть утилит)    |
|  **2.3.4** | Права в `$HOME` (dotfiles)           | `chmod go-rwx` на `.bashrc/.profile/.rhosts`          |        🟡       |                   ⚪                   |
|  **2.3.5** | Автозагрузка (rc/systemd)            | Права на `rc.local/rc*.d` и юниты systemd             |        🟡       |                   ⚪                   |
|  **2.3.6** | User-cron                            | Жёсткие права `/var/spool/cron`                       |        🟡       |                   🟡                  |
|  **2.3.7** | Ограничение `at`                     | Права `/var/spool/at`, `at.deny` (или удалить пакет)  |        🟡       |                   🟡                  |
|  **2.3.8** | Права на `bin/sbin/lib*`             | 755/750, `root:root`                                  |        🔴       |                   ⚪                   |
|  **2.3.9** | Контроль системных бинарей           | Проверка/исправление записываемости                   |        🟡       |                   ⚪                   |
| **2.3.10** | Домашние файлы (истории)             | `chmod go-rwx` на `.bash_history` и др.               |        🟡       |                   ⚪                   |
| **2.3.11** | Домашние каталоги                    | `chmod 700` на каталоги пользователей                 |        🟡       |                   ⚪                   |
|  **2.4.1** | `kernel.dmesg_restrict=1`            | `sysctl`                                              |        🟡       |    🟡 (ограничивает отладку dmesg)    |
|  **2.4.2** | `kernel.kptr_restrict=2`             | `sysctl`                                              |        🟡       |                   ⚪                   |
|  **2.4.3** | `init_on_alloc=1`                    | GRUB параметр                                         |        🟡       |        🟡 (небольшая просадка)        |
|  **2.4.4** | `slab_nomerge`                       | GRUB параметр                                         |        🟡       |           🟡 (потенц. ↑ RAM)          |
|  **2.4.5** | IOMMU: `force/strict`                | GRUB параметр                                         |        🟡       |    🔴 (совместимость PCI/драйверов)   |
|  **2.4.6** | `randomize_kstack_offset=1`          | GRUB параметр                                         |        🟡       |                   ⚪                   |
|  **2.4.7** | `mitigations=auto,nosmt`             | GRUB параметр                                         |        🟡       |      🔴 (просадка из-за SMT off)      |
|  **2.4.8** | `net.core.bpf_jit_harden=2`          | `sysctl`                                              |        🟡       |        🟡 (сложнее отладка BPF)       |
|  **2.5.1** | `vsyscall=none`                      | GRUB параметр                                         |        🟡       |        🔴 (ломает старый софт)        |
|  **2.5.2** | `kernel.perf_event_paranoid=3`       | `sysctl`                                              |        🟡       |         🟡 (ограничивает perf)        |
|  **2.5.3** | `debugfs=off`                        | GRUB параметр                                         |        🟡       |            🟡 (нет debugfs)           |
|  **2.5.4** | `kernel.kexec_load_disabled=1`       | `sysctl`                                              |        🟡       |       🟡 (нет kexec/live-reboot)      |
|  **2.5.5** | `user.max_user_namespaces=0`         | `sysctl`                                              |        🟡       |    🔴 (ломает rootless-контейнеры)    |
|  **2.5.6** | `kernel.unprivileged_bpf_disabled=1` | `sysctl`                                              |        🟡       |                   🟡                  |
|  **2.5.7** | `vm.unprivileged_userfaultfd=0`      | `sysctl`                                              |        🟡       |                   ⚪                   |
|  **2.5.8** | `dev.tty.ldisc_autoload=0`           | `sysctl`                                              |        🟡       |                   ⚪                   |
|  **2.5.9** | `tsx=off`                            | GRUB параметр                                         |        🟡       |  🟡 (небольшая просадка на Intel TSX) |
| **2.5.10** | `vm.mmap_min_addr ≥ 4096`            | `sysctl` (реком. 65536)                               |        🟡       |    🔴 (может ломать Wine/эмуляторы)   |
| **2.5.11** | `kernel.randomize_va_space=2`        | `sysctl`                                              |        🔴       |                   ⚪                   |
|  **2.6.1** | `kernel.yama.ptrace_scope=3`         | `sysctl`                                              |        🟡       | 🔴 (ломает классический ptrace-debug) |
|  **2.6.2** | `fs.protected_symlinks=1`            | `sysctl`                                              |        🟡       |                   ⚪                   |
|  **2.6.3** | `fs.protected_hardlinks=1`           | `sysctl`                                              |        🟡       |                   ⚪                   |
|  **2.6.4** | `fs.protected_fifos=2`               | `sysctl`                                              |        🟡       |                   ⚪                   |
|  **2.6.5** | `fs.protected_regular=2`             | `sysctl`                                              |        🟡       |                   ⚪                   |
|  **2.6.6** | `fs.suid_dumpable=0`                 | `sysctl`                                              |        🟡       |                   ⚪                   |
