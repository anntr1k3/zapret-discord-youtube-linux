<div align="center">

# 🎧 Zapret Discord YouTube Linux 📺

### Автономный порт и адаптер обхода замедления Discord & YouTube для Linux

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/anntr1k3/zapret-discord-youtube-linux?style=social)](https://github.com/anntr1k3/zapret-discord-youtube-linux/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/anntr1k3/zapret-discord-youtube-linux?style=social)](https://github.com/anntr1k3/zapret-discord-youtube-linux/network/members)

На базе стратегий [Flowseal](https://github.com/Flowseal/zapret-discord-youtube) и утилиты [zapret](https://github.com/bol-van/zapret) от bol-van  
Соавтор первоначальной адаптации: [Sergeydigl3](https://github.com/Sergeydigl3/zapret-discord-youtube-linux)

**Проверено на:**
Ubuntu 24.04 • Debian 12 • Arch Linux • Fedora • Gentoo Linux

</div>

---

<div align="center">

[Быстрый старт](#быстрый-старт) • [Использование](#использование) • [Автозагрузка](#автозагрузка) • [Поддержка](#поддержка-и-помощь)


</div>

## Быстрый старт

```bash
git clone https://github.com/anntr1k3/zapret-discord-youtube-linux.git
cd zapret-discord-youtube-linux

./service.sh download-deps --default
./service.sh
```

Скрипт интерактивно предложит выбрать действие: запуск, управление сервисом или настройку конфигурации.

> 🚀 **Релиз 1.0 (Полный паритет с Flowseal service.bat v1.10.4):**
> Добавлен полноценный нативный графический интерфейс на **GTK4 / libadwaita** с нулевой потребностью в терминале, безопасным разделением привилегий (pkexec root-помощник), встроенным тестировщиком стратегий, глубокой диагностикой конфликтов и ярлыком рабочего стола. Подробнее: [Release Notes v1.0](RELEASE_NOTES_v1.0.md) и [документация GUI](docs/gui.md).

> ⚠️ **Безопасность:** создание широких правил NOPASSWD отключено. Привилегированные операции требуют обычного подтверждения sudo/doas/polkit. Подробнее: [изменения безопасности](docs/security-hardening.md).

> **Системная установка (systemd):** управление сервисом доступно как из графического окна (кнопки установки и удаления), так и через [CLI-установщик с обновлением и откатом](docs/system-install.md).

Краткая памятка: [основные команды](docs/commands.md) · [горячая клавиша остановки](docs/desktop-shortcut.md).

[Автосинхронизация Flowseal](docs/strategy-sync.md): ежедневная подготовка без root, проверка nfqws и применение только с подтверждением; рабочая версия не меняется автоматически.

[Графический интерфейс GTK4](docs/gui.md):
- `python3 gui.py --demo` — безопасный демо-режим без прав root и без изменения системы;
- `python3 gui.py` — полноценное управление обходом DPI;
- `./src/desktop/install-desktop.sh --user` — установка ярлыка и иконки приложения в меню GNOME/KDE.

> 💡 Что-то не работает? Сначала прочитайте раздел [Поддержка и помощь](#поддержка-и-помощь)

---

**Требования:**
- Бэкенды firewall: **nftables** (приоритет при автоопределении) или **iptables + ip6tables**
- Поддерживаемые архитектуры: **x86_64, ARM, MIPS, и др** (автоматическое определение)

---

## О версиях

Адаптер по умолчанию использует:
- **nfqws**: v72.9 (рекомендованная версия, прописана в `src/lib/constants.sh` как `ZAPRET_RECOMMENDED_VERSION`)
- **Стратегии**: [коммит ef19845a801e4e743f7bdfdbd58f9745c6adbd60](https://github.com/Flowseal/zapret-discord-youtube/commit/ef19845a801e4e743f7bdfdbd58f9745c6adbd60) (прописан в `src/lib/constants.sh` как `MAIN_REPO_REV`)

Вы можете изменить версии:
- Интерактивно: `./service.sh download-deps` (выбор из доступных версий)
- Напрямую: `./service.sh download-deps -z v72.9 -s main`
- В коде: отредактируйте константы в `src/lib/constants.sh`

Если текущая версия не работает, попробуйте [стабильные релизы](https://github.com/anntr1k3/zapret-discord-youtube-linux/releases).

**Сторонние проекты:**
- [Версия от Snowy-Fluffy](https://github.com/Snowy-Fluffy/zapret.installer)

---

# Использование

## Интерактивный режим

```bash
./service.sh
```

Меню предлагает:
1. **Запустить** — интерактивный выбор интерфейса, gamefilter и стратегии, запуск в текущем терминале
2. **Управление сервисом** — установка/удаление/перезапуск системного сервиса
3. **Изменить конфигурацию** — редактирование `conf.env`

## Конфигурация (conf.env)

Создайте файл `conf.env`:

```bash
strategy=general.bat
interface=enp0s3
gamefiltertcp=true
gamefilterudp=true
```

## Управление через CLI

### Основные команды

```bash
./service.sh --help  # показать справку по командам
```

### Управление зависимостями

```bash
# Скачать nfqws и стратегии (интерактивный выбор версий)
./service.sh download-deps

# Скачать рекомендованные версии (неинтерактивно)
./service.sh download-deps --default

# Скачать конкретные версии
./service.sh download-deps -z v72.9 -s main

# Показать доступные стратегии
./service.sh strategy list
```

### Запуск zapret

```bash
# Интерактивный режим (запрос параметров)
./service.sh run

# Загрузка из конфигурационного файла
./service.sh run --config conf.env

# Прямые параметры
./service.sh run -s general.bat -i enp0s3
./service.sh run -s general.bat -i enp0s3 -gt -gu  # с gamefiltertcp и gamefilterudp
```

### Управление системным сервисом

```bash
# Интерактивное меню управления сервисом
./service.sh service

# Установить и запустить сервис
./service.sh service install

# Показать статус
./service.sh service status

# Запустить/остановить/перезапустить
./service.sh service start
./service.sh service stop
./service.sh service restart

# Удалить сервис
./service.sh service remove
```

### Управление конфигурацией

```bash
# Показать текущую конфигурацию
./service.sh config show

# Интерактивное редактирование
./service.sh config edit

# Установить конфигурацию напрямую
./service.sh config set general.bat
./service.sh config set general.bat enp0s3 -gt -gu  # с gamefiltertcp и gamefilterudp
./service.sh config set discord -n             # без перезапуска сервиса
```

### Создание ярлыка в меню приложений

```bash
# Создать ярлык в меню приложений (для GUI запуска)
./service.sh desktop install

# Удалить ярлык из меню приложений
./service.sh desktop remove
```

После установки ярлыка вы сможете запустить zapret из меню приложений вашей системы (категория "Сеть" или "Система").

### Утилиты

```bash
# Остановить nfqws и очистить nftables
./service.sh kill
```

---

## Автоматический подбор стратегий

```bash
./auto_tune_youtube.sh
```

Скрипт автоматически:
1. Перебирает стратегии из `/custom-strategies` и `/zapret-latest` (начинающиеся на `general`)
2. Тестирует доступ к YouTube
3. Сохраняет результаты в `auto_tune_youtube_results.txt`
4. Предлагает запустить или сохранить рабочую стратегию в `conf.env`

> Функционал экспериментальный, достоверность не гарантирована

-----
```bash
./auto_tune.sh
```

Скрипт для проверки любого домена:
1. Перебирает стратегии из `/custom-strategies` и `/zapret-latest` (начинающиеся на `general`)
2. Тестирует доступ ко всем указанным через пробел доменам
3. Сохраняет стратегии сработавшие только на все указанные домены в auto_tune_results.sh

> Функционал также экспериментальный


---

## Автозагрузка (системный сервис)

```bash
# Через CLI
./service.sh service install

# Или через интерактивное меню
./service.sh
# -> выбрать "2. Управление сервисом" -> "1. Установить и запустить сервис"
```

Скрипт:
- Проверяет `conf.env` (если пустой — запросит параметры интерактивно)
- Создаёт сервис для автозапуска (поддерживает systemd, OpenRC, runit, s6, dinit)
- Использует значения из `conf.env`

<details>
<summary>Для systemd систем</summary>

Просмотреть статус сервиса можно командой:

```bash
systemctl status zapret_discord_youtube.service
```

Посмотреть логи сервиса:

```bash
journalctl -u zapret_discord_youtube.service
```

</details>

<details>
<summary>Для OpenRC систем</summary>

Просмотреть статус сервиса можно командой:

```bash
rc-service zapret_discord_youtube status
```

Посмотреть логи сервиса:

```bash
rc-service zapret_discord_youtube logs
```

</details>

<details>
<summary>Для runit систем</summary>

Просмотреть статус сервиса можно командой:

```bash
sv status zapret_discord_youtube
```

Посмотреть логи сервиса:

```bash
tail -f /var/log/zapret_discord_youtube/current
```

</details>

<details>
<summary>Для s6 систем</summary>

Просмотреть статус сервиса можно командой:

```bash
s6-svstat /var/service/zapret_discord_youtube
```

Посмотреть логи сервиса:

```bash
tail -f /var/log/zapret_discord_youtube/current
```

</details>

<details>
<summary>Для dinit систем</summary>

Просмотреть статус сервиса можно командой:

```bash
dinitctl status zapret_discord_youtube
```

Посмотреть логи сервиса:

```bash
dinitctl log zapret_discord_youtube
```

</details>

---

## Поддержка и помощь

> [!IMPORTANT]
> Это АДАПТЕР! Не гарантирует, что стратегии разблокируют всё.

### Если ничего не работает

**Прежде чем создавать Issue или Discussion:**

1. Посмотрите [Issues в репозитории со стратегиями](https://github.com/Flowseal/zapret-discord-youtube/issues) — возможно, проблема уже обсуждается там
2. Попробуйте другие стратегии или воспользуйтесь [автоматическим подбором](#автоматический-подбор-стратегий)
3. Проверьте [Discussions](https://github.com/Flowseal/zapret-discord-youtube/discussions) — там обсуждают рабочие решения

### Когда создавать Issue / Discussion

**Когда писать в [Issues](https://github.com/anntr1k3/zapret-discord-youtube-linux/issues):**
- Ошибки в работе GUI или консольных скриптов адаптера
- Неисправности в системном сервисе или Polkit root-помощнике
- Предложения по добавлению новых возможностей в адаптер

**Когда писать в [Discussions](https://github.com/anntr1k3/zapret-discord-youtube-linux/discussions):**
- Не работает YouTube или Discord (после проверки основного репозитория Flowseal)
- Поиск и обсуждение оптимальных рабочих стратегий под конкретных провайдеров
- Обмен опытом настройки в различных дистрибутивах Linux

---

## 👥 Авторы и благодарности

Проект развивается самостоятельно и выражает искреннюю благодарность создателям базовых инструментов:

- **[bol-van](https://github.com/bol-van/zapret)** — автор фундаментальной утилиты `zapret` и демона `nfqws` (NFQUEUE).
- **[Flowseal](https://github.com/Flowseal/zapret-discord-youtube)** — автор оригинального Windows-решения `zapret-discord-youtube`, базы стратегий, пакетов фейков и списков доменов/IP.
- **[Sergeydigl3](https://github.com/Sergeydigl3/zapret-discord-youtube-linux)** — соавтор, создатель первоначальной адаптации скриптов запуска под Linux.
- **[anntr1k3](https://github.com/anntr1k3/zapret-discord-youtube-linux)** — автор релиза v1.0, графического интерфейса GTK4/libadwaita, безопасного Polkit root-помощника, потокового тестировщика стратегий и углублённой диагностики.

---

## 🤝 Содействие проекту (Contributing)

Pull Request'ы и сообщения об ошибках приветствуются!
- Сообщить об ошибке: [Issues](https://github.com/anntr1k3/zapret-discord-youtube-linux/issues)
- Задать вопрос / Обсудить: [Discussions](https://github.com/anntr1k3/zapret-discord-youtube-linux/discussions)
- Отправить Pull Request: [Pull Requests](https://github.com/anntr1k3/zapret-discord-youtube-linux/pulls)

---

## 📄 Лицензия

Проект распространяется под открытой лицензией [MIT](LICENSE).
