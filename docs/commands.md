# Основные команды

Команды systemctl относятся к системной установке через `install.py`, а не к
ручному запуску `service.sh run`. Не запускайте оба режима одновременно:
адаптер использует общие имена таблиц firewall и одну очередь.

## Первоначальная подготовка

Из каталога проекта:

```sh
cd ~/Документы/zapret-discord-youtube-linux
./service.sh download-deps --default
./service.sh config set general -n
```

Первой командой скачиваются выбранные рекомендованные зависимости/стратегии.
Вторая записывает конфиг для `general.bat` без перезапуска сервиса. Стратегия
`general.bat` — только начальный вариант, её работа у любого провайдера не
гарантируется.

Установить проверенную подготовленную копию, запустить и включить автозапуск:

```sh
sudo python3 install.py install --source "$PWD" --start
```

Эта команда меняет систему и запускает обработку трафика. Подробнее:
[установщик и ограничения](system-install.md).

## Ежедневное управление установленным сервисом

Из любого каталога:

```sh
# Состояние (выход — q, если открыт просмотрщик)
systemctl status zapret_discord_youtube.service

# Запустить / остановить / перезапустить
sudo systemctl start zapret_discord_youtube.service
sudo systemctl stop zapret_discord_youtube.service
sudo systemctl restart zapret_discord_youtube.service

# Выключить вместе с автозапуском
sudo systemctl disable --now zapret_discord_youtube.service

# Включить вместе с автозапуском
sudo systemctl enable --now zapret_discord_youtube.service

# Последние 50 строк журнала
sudo journalctl -u zapret_discord_youtube.service -n 50 --no-pager

# Журнал в реальном времени (Ctrl+C завершит просмотр, не сервис)
sudo journalctl -u zapret_discord_youtube.service -f
```

Обычный `stop` и горячая клавиша **не выключают автозапуск**. После перезагрузки
включённый сервис снова запустится. [Горячая клавиша остановки](desktop-shortcut.md).

## Конфигурация и списки установленной версии

```sh
sudoedit /etc/zapret-discord-youtube/conf.env
sudoedit /etc/zapret-discord-youtube/user-lists/list-general-user.txt
sudo systemctl restart zapret_discord_youtube.service
```

В конфиге выбирается `strategy=ИМЯ.bat` из имеющихся стратегий. Формат —
`key=value`, без кавычек и shell-кода. Перед изменением `firewall_backend`
сначала остановите сервис, чтобы старый бэкенд корректно очистил свои правила.
Не редактируйте версии кода и файлы списков внутри `/opt` на месте.

## Проверка вручную, без системной установки

Из подготовленного каталога проекта, при остановленном системном сервисе:

```sh
./service.sh strategy list
./service.sh config set general -n
./service.sh run --config conf.env
```

Остановить ручной запуск — **Ctrl+C в его терминале**. Горячая клавиша для
systemd-сервиса этот режим не останавливает. Параметры записываются в локальный
`conf.env`, а не в конфиг уже установленной системной копии.

`./service.sh` открывает исходное интерактивное меню адаптера. Это пока не
полноценный аналог Flowseal `service.bat`; системную установку/удаление выполняйте
через `install.py`, а запуск/остановку — через systemctl.

## Обновление, откат и удаление

Из проверенного checkout с подготовленными зависимостями:

```sh
sudo python3 install.py update --source "$PWD"
sudo python3 install.py rollback
sudo python3 install.py remove
```

`update` устанавливает содержимое указанной папки, а не скачивает свежие
стратегии автоматически. `rollback` возвращает предыдущий код, сохраняя текущие
настройки и списки. `remove` удаляет управляемый сервис и код, но сохраняет
пользовательские данные и резервные копии.

## Синхронизация только стратегий

После однократного перехода на версию с синхронизацией:

```sh
python3 sync.py check
python3 sync.py prepare
python3 sync.py status
```

Проверка/подготовка не останавливает сервис. Применение требует отдельной команды
`install.py apply-strategies` с stage, его digest и подтверждением; есть
пользовательский таймер для ежедневной подготовки. Полные команды и ограничения:
[автосинхронизация Flowseal](strategy-sync.md).
