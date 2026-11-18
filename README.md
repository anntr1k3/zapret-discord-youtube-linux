# Zapret для Linux

Linux-адаптер [zapret](https://github.com/bol-van/zapret) и профилей
[Flowseal](https://github.com/Flowseal/zapret-discord-youtube) с русским
интерфейсом GTK4/libadwaita. Из окна можно управлять systemd-сервисом,
выбирать стратегии, читать журнал и запускать диагностику.

**[Скачать предварительную версию `1.0.1-rc1`](https://github.com/anntr1k3/zapret-discord-youtube-linux/releases/tag/v1.0.1-rc1)** ·
[Что проверено](https://github.com/anntr1k3/zapret-discord-youtube-linux/blob/v1.0.1-rc1/docs/trusted-bootstrap.md) ·
[Сообщить о проблеме](https://github.com/anntr1k3/zapret-discord-youtube-linux/issues/new/choose)

## Установка из `.deb`

Пакет проверен на **Ubuntu 24.04 LTS, amd64**. Для GUI нужна libadwaita 1.5
или новее. Другие дистрибутивы и архитектуры для этого пакета не проверены.

1. Со страницы prerelease скачайте `.deb` и `SHA256SUMS` в один каталог.
2. Проверьте контрольную сумму. Только если проверка успешна, установите пакет:

   ```sh
   sha256sum --check SHA256SUMS &&
     sudo apt install ./zapret-discord-youtube_1.0.1-rc1_amd64.deb
   ```

3. Запустите `zapret-gui` обычным пользователем. Чтобы включить обход,
   откройте **Сервис → Установить системный сервис** и подтвердите действие.

Пакет устанавливает окно и доверенный помощник, но **сам не запускает сервис**.
При удалении сервиса из GUI приложение остаётся, а настройки и списки
сохраняются, если не выбрать удаление данных.

> Не используйте старый `.deb` `v1.0.0` для новой установки сервиса из GUI:
> в нём нет доверенного помощника первоначальной установки. Стабильный архив
> сохранён для истории и сравнения.

## Попробовать интерфейс без установки

Из локального checkout, при наличии Python GI, GTK4 и libadwaita ≥ 1.5:

```sh
python3 gui.py --demo
```

Демо не меняет конфигурацию, сервис и firewall. Checkout не заменяет
установку пакета для системных операций. Не запускайте GUI через `sudo`.

## Документация

| Задача | Где читать |
| --- | --- |
| Установка, удаление и проверка нового пакета | [Доверенная установка](https://github.com/anntr1k3/zapret-discord-youtube-linux/blob/v1.0.1-rc1/docs/trusted-bootstrap.md) |
| Список команд и ручная установка | [Команды](docs/commands.md) · [Системный установщик](docs/system-install.md) |
| Диагностика, журнал и тестирование | [Диагностика](docs/diagnostics.md) · [Состояние сервиса](docs/service-status.md) · [Тестировщик](docs/strategy-tester.md) |
| Настройки стратегий | [Game Filter](docs/game-filter.md) · [IPSet](docs/ipset-modes.md) · [Синхронизация Flowseal](docs/strategy-sync.md) |
| Проверка в своей сети | [Чек-лист YouTube, Discord и QUIC](https://github.com/anntr1k3/zapret-discord-youtube-linux/blob/v1.0.1-rc1/docs/gui-acceptance.md) |

В VM проверены чистая установка, обновление с чистого `v1.0.0`, повторная
установка сервиса и графическая авторизация polkit. Это не доказывает
эффективность обхода: воспроизведение YouTube, голос Discord и QUIC
в пользовательских сетях пока не подтверждены.

Для отчёта об ошибке укажите дистрибутив, версию пакета, выбранную стратегию
и шаги воспроизведения. Удалите токены и личные данные из приложенных логов.

Проект основан на работе [bol-van](https://github.com/bol-van/zapret),
[Flowseal](https://github.com/Flowseal/zapret-discord-youtube) и первоначальной
Linux-адаптации [Sergeydigl3](https://github.com/Sergeydigl3/zapret-discord-youtube-linux).
Лицензия проекта — [MIT](LICENSE).
