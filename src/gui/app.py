"""Russian GTK4/libadwaita shell. Administrative work stays in the backend."""

import argparse
import os
from pathlib import Path
import sys
import threading

from .backend import Backend, DemoBackend
from .presentation import operation_messages, profile_index, game_filter_values, version_text, service_status_text, service_state_title, diagnostics_text, tester_text
from ..lib.strategy_sync import validate_game_ports


GAME_MODES = ("disabled", "tcp", "udp", "all")
GAME_LABELS = ("Выключен", "Только TCP", "Только UDP", "TCP и UDP")
IPSET_MODES = (None, "loaded", "none", "any")
IPSET_LABELS = ("Выберите режим", "Загруженный список (loaded)", "Заглушка IPSet (none)", "Все адреса (any)")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Графический интерфейс zapret")
    parser.add_argument("--demo", action="store_true", help="симуляция без системных действий")
    parser.add_argument("--tester", action="store_true", help="открыть вкладку тестировщика (без запуска тестов)")
    parser.add_argument("--smoke-test", action="store_true", help="автопроверка окна; только с --demo")
    args = parser.parse_args(argv)
    if args.smoke_test and not args.demo:
        parser.error("--smoke-test разрешён только с --demo")
    if os.geteuid() == 0:
        parser.error("Запустите окно обычным пользователем, без sudo")
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw, Gio, GLib, Gtk
        if (Adw.get_major_version(), Adw.get_minor_version()) < (1, 5):
            raise ValueError("требуется libadwaita 1.5 или новее")
    except (ImportError, ValueError) as error:
        print(f"Необходимы Python GI, GTK4 и libadwaita: {error}", file=sys.stderr)
        return 1

    class Application(Adw.Application):
        def __init__(self):
            super().__init__(application_id="io.github.zapret.LinuxGUI",
                             flags=Gio.ApplicationFlags.NON_UNIQUE)
            self.backend = DemoBackend() if args.demo else Backend(Path(__file__).resolve().parents[2])
            self.busy = False
            self.state = {}
            self.failed = False
            self.smoke_index = 0
            self.smoke_last_action = "refresh"
            self.smoke_expected_error = False
            self.current_toast = None
            self.error_text = ""
            self.tester_cancel_event = None
            self.tester_checks = []

        def do_activate(self):
            if hasattr(self, "window"):
                self.window.present()
                return
            self.window = Adw.ApplicationWindow(application=self, title="Zapret · Демо" if args.demo else "Zapret")
            self.window.set_default_size(820, 680)
            self.window.connect("close-request", self.close_requested)
            self.toast = Adw.ToastOverlay()
            self.window.set_content(self.toast)
            outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            self.toast.set_child(outer)
            header = Adw.HeaderBar()
            outer.append(header)
            if args.demo:
                banner = Adw.Banner(title="Демонстрация: сервис, firewall и настройки не изменяются", revealed=True)
                outer.append(banner)
            self.error_banner = Adw.Banner(title="Возникла ошибка — откройте подробности", button_label="Подробности", revealed=False)
            self.error_banner.connect("button-clicked", lambda *_: self.show_error_details())
            outer.append(self.error_banner)
            stack = Gtk.Stack(vexpand=True)
            self.pages = stack
            switcher = Gtk.StackSwitcher(stack=stack, halign=Gtk.Align.CENTER)
            outer.append(switcher)
            outer.append(stack)
            self.progress = Gtk.Revealer(transition_type=Gtk.RevealerTransitionType.SLIDE_UP)
            progress_box = Gtk.Box(spacing=10)
            for edge in ("top", "bottom", "start", "end"):
                getattr(progress_box, "set_margin_" + edge)(12)
            self.spinner = Gtk.Spinner()
            progress_box.append(self.spinner)
            self.progress_label = Gtk.Label(wrap=True, xalign=0)
            self.progress_label.add_css_class("dim-label")
            progress_box.append(self.progress_label)
            # Outside self.pages: disabling the stack must not disable cancel.
            self.tester_cancel = self.button(progress_box, "Прервать тест", self.cancel_tester)
            self.tester_cancel.set_sensitive(False)
            self.progress.set_child(progress_box)
            outer.append(self.progress)
            page = self.page(stack, "service", "Сервис")
            self.status = Gtk.Label(label="Чтение состояния…", wrap=True, xalign=0)
            self.status.add_css_class("title-1")
            page.append(self.status)
            self.detail = Gtk.Label(wrap=True, xalign=0)
            page.append(self.detail)
            row = Gtk.Box(spacing=8)
            page.append(row)
            self.start = self.button(row, "Запустить", lambda: self.service("start"))
            self.stop = self.button(row, "Остановить", lambda: self.service("stop"))
            self.restart = self.button(row, "Перезапустить", lambda: self.service("restart"))
            self.button(page, "Обновить состояние", self.refresh)
            self.autostart = self.button(page, "Автозапуск", self.toggle_autostart)
            self.install_btn = self.button(page, "Установить системный сервис…", self.install_service_action)
            self.remove_btn = self.button(page, "Удалить системный сервис…", self.remove_service_action)
            self.service_note = Gtk.Label(label="Управляются только процессы установленного systemd-сервиса.\nРучной запуск service.sh это окно не останавливает.", wrap=True, xalign=0)
            page.append(self.service_note)
            self.service_sep = Gtk.Separator()
            page.append(self.service_sep)
            self.read_service_status = self.button(page, "Прочитать расширенный статус…",
                lambda: self.run_operation(self.backend.read_status, action="read-status"))
            self.service_report = Gtk.Label(wrap=True, xalign=0, selectable=True)
            page.append(self.service_report)

            page = self.page(stack, "profiles", "Стратегия")
            page.append(Gtk.Label(label="Конфиг читается только по запросу с авторизацией.\nСмена профиля перезапускает только уже работающий сервис.", wrap=True, xalign=0))
            self.load = self.button(page, "Прочитать настройки…", lambda: self.run_operation(self.backend.load_config, action="read-config"))
            self.profile_info = Gtk.Label(label="Настройки ещё не прочитаны", xalign=0, wrap=True)
            page.append(self.profile_info)
            self.profiles = Gtk.DropDown(model=Gtk.StringList.new([]))
            page.append(self.profiles)
            self.select = self.button(page, "Применить профиль…", self.select_profile)

            page = self.page(stack, "settings", "Настройки")
            heading = Gtk.Label(label="Game Filter", xalign=0)
            heading.add_css_class("title-2")
            page.append(heading)
            page.append(Gtk.Label(label="Добавляет в стратегию выбранные игровые порты.\nШирокие диапазоны могут затронуть другие приложения.\nРаботающий сервис будет перезапущен только после подтверждения.", wrap=True, xalign=0))
            self.load_settings = self.button(page, "Прочитать настройки…", lambda: self.run_operation(self.backend.load_config, action="read-config"))
            self.game_info = Gtk.Label(wrap=True, xalign=0)
            page.append(self.game_info)
            self.game_mode = Gtk.DropDown(model=Gtk.StringList.new([]))
            page.append(self.game_mode)
            page.append(Gtk.Label(label="Порты TCP", xalign=0))
            self.game_tcp = Gtk.Entry(placeholder_text="1024-65535", max_length=512)
            page.append(self.game_tcp)
            page.append(Gtk.Label(label="Порты UDP", xalign=0))
            self.game_udp = Gtk.Entry(placeholder_text="1024-65535", max_length=512)
            page.append(self.game_udp)
            page.append(Gtk.Label(label="Числа 1–65535 и возрастающие диапазоны через запятую.\nНапример: 1024-1934,1936-65535. Диапазоны сохраняются и в выключенном режиме.", wrap=True, xalign=0))
            self.save_game = self.button(page, "Применить Game Filter…", self.set_game_filter)

            page.append(Gtk.Separator())
            heading = Gtk.Label(label="IPSet", xalign=0)
            heading.add_css_class("title-2")
            page.append(heading)
            page.append(Gtk.Label(label="Режим меняет только основной фильтр ipset-all.txt.\nСписки доменов, пользовательские исключения и отдельные Game Filter-профили сохраняются.\n«Все адреса» действует в пределах фильтров выбранной стратегии.", wrap=True, xalign=0))
            self.ipset_info = Gtk.Label(wrap=True, xalign=0, selectable=True)
            page.append(self.ipset_info)
            self.ipset_mode = Gtk.DropDown(model=Gtk.StringList.new([]))
            self.ipset_mode.connect("notify::selected", lambda *_: self.update_ipset_button())
            page.append(self.ipset_mode)
            self.save_ipset = self.button(page, "Применить режим IPSet…", self.set_ipset_mode)
            self.ipset_update = self.button(page, "Обновить список IPSet…", self.update_ipset)

            page.append(Gtk.Separator())
            heading = Gtk.Label(label="Активные fakes", xalign=0)
            heading.add_css_class("title-2")
            page.append(heading)
            page.append(Gtk.Label(label="Замена fake-пакетов для Discord UDP (fake-discord, fake-stun)\nи GameFilter UDP (fake-unknown-udp) на файлы из установленного релиза.\nUpstream-набор не изменяется; работающий сервис перезапускается после подтверждения.", wrap=True, xalign=0))
            self.fakes_info = Gtk.Label(wrap=True, xalign=0, selectable=True)
            page.append(self.fakes_info)
            page.append(Gtk.Label(label="Discord UDP", xalign=0))
            self.fake_discord = Gtk.DropDown(model=Gtk.StringList.new([]))
            self.fake_discord.connect("notify::selected", lambda *_: self.update_fakes_button())
            page.append(self.fake_discord)
            page.append(Gtk.Label(label="GameFilter UDP", xalign=0))
            self.fake_gameudp = Gtk.DropDown(model=Gtk.StringList.new([]))
            self.fake_gameudp.connect("notify::selected", lambda *_: self.update_fakes_button())
            page.append(self.fake_gameudp)
            self.save_fakes = self.button(page, "Применить активные fakes…", self.set_active_fakes)

            page.append(Gtk.Separator())
            heading = Gtk.Label(label="Hosts", xalign=0)
            heading.add_css_class("title-2")
            page.append(heading)
            page.append(Gtk.Label(label="Добавляет или заменяет только управляемый блок между служебными маркерами.\nОстальные строки /etc/hosts, владелец и права файла сохраняются.\nПеред записью создаётся резервная копия; сервис не перезапускается.", wrap=True, xalign=0))
            self.hosts_info = Gtk.Label(wrap=True, xalign=0, selectable=True)
            page.append(self.hosts_info)
            self.hosts_update = self.button(page, "Проверить и обновить hosts…", self.update_hosts)

            page = self.page(stack, "updates", "Обновления")
            heading = Gtk.Label(label="Версии приложения и данных", xalign=0)
            heading.add_css_class("title-2")
            page.append(heading)
            self.version_info = Gtk.Label(wrap=True, xalign=0, selectable=True)
            page.append(self.version_info)
            self.flowseal_source = Gtk.LinkButton(uri="https://github.com/Flowseal/zapret-discord-youtube",
                                                  label="Источник данных: Flowseal", halign=Gtk.Align.START)
            page.append(self.flowseal_source)
            self.current_data_link = Gtk.LinkButton(uri="https://github.com/Flowseal/zapret-discord-youtube",
                                                    label="Источник локального набора", halign=Gtk.Align.START)
            page.append(self.current_data_link)
            self.checked_data_link = Gtk.LinkButton(uri="https://github.com/Flowseal/zapret-discord-youtube",
                                                    label="Релиз / commit по последней проверке", halign=Gtk.Align.START)
            page.append(self.checked_data_link)
            page.append(Gtk.Separator())
            self.auto_check_info = Gtk.Label(wrap=True, xalign=0, selectable=True)
            page.append(self.auto_check_info)
            self.auto_check_toggle = self.button(page, "Автоматическая проверка…", self.toggle_auto_check)
            self.button(page, "Обновить сведения о проверке", self.refresh)
            page.append(Gtk.Label(label="Проверка выполняется ежедневно в пользовательском сеансе systemd, с задержкой до 30 минут.\nПропущенная проверка может выполниться при следующем входе. Работа без входа в систему не включается.\nТаймер только проверяет сведения Flowseal: стратегии не скачиваются и не применяются.", wrap=True, xalign=0))
            page.append(Gtk.Separator())
            page.append(Gtk.Label(label="Проверка и подготовка выполняются без root.\nСведения о релизе кэшируются на 15 минут.\nПрименение обновления требует отдельного подтверждения.", wrap=True, xalign=0))
            self.button(page, "Проверить Flowseal", lambda: self.run_operation(self.backend.check_update, self.show_update, action="check"))
            self.button(page, "Подготовить обновление", lambda: self.run_operation(self.backend.prepare_update, self.show_update, action="prepare"))
            self.update_info = Gtk.Label(wrap=True, xalign=0, selectable=True)
            page.append(self.update_info)
            self.apply = self.button(page, "Применить подготовленное…", self.apply_update)

            page = self.page(stack, "diagnostics", "Диагностика")
            page.append(Gtk.Label(label="Сбор отчёта — только локальные наблюдения, без root, сетевых проб и исправлений. Действия обслуживания ниже запускаются отдельно.\nОтчёт может содержать локальные пути, DNS/proxy-хосты и PID. Просмотрите его перед передачей другим.\nПароли прокси, пути/query URL и содержимое no_proxy не включаются.", wrap=True, xalign=0))
            self.button(page, "Собрать отчёт", lambda: self.run_operation(self.backend.diagnostics, action="diagnostics"))
            row = Gtk.Box(spacing=8)
            page.append(row)
            self.diagnostics_copy = self.button(row, "Скопировать отчёт", self.copy_diagnostics)
            self.diagnostics_export = self.button(row, "Экспорт JSON…", self.choose_diagnostics_export)
            self.diagnostics_view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True,
                                                 wrap_mode=Gtk.WrapMode.WORD_CHAR)
            scroll = Gtk.ScrolledWindow(vexpand=True, min_content_height=320)
            scroll.set_child(self.diagnostics_view)
            page.append(scroll)
            page.append(Gtk.Label(label="Для привилегированных сведений о процессе и firewall используйте расширенный статус на вкладке «Сервис».", wrap=True, xalign=0))
            page.append(Gtk.Separator())
            heading = Gtk.Label(label="TCP timestamps · текущая загрузка", xalign=0)
            heading.add_css_class("title-2")
            page.append(heading)
            page.append(Gtk.Label(label="Отдельное административное действие: включить net.ipv4.tcp_timestamps только в работающем ядре.\nЭто системный TCP-параметр текущего network namespace, не настройка одного zapret. Эффективность обхода DPI не гарантируется.\nЗначения 1 и 2 уже означают включённые timestamps и не переписываются. Конфиг, sysctl.d, автозапуск и сервис zapret не меняются.", wrap=True, xalign=0))
            self.read_tcp = self.button(page, "Прочитать TCP timestamps…", lambda: self.run_operation(
                self.backend.read_tcp_timestamps, action="read-tcp-timestamps"))
            self.tcp_info = Gtk.Label(wrap=True, xalign=0, selectable=True)
            page.append(self.tcp_info)
            self.enable_tcp = self.button(page, "Включить TCP timestamps…", self.enable_tcp_timestamps)
            page.append(Gtk.Separator())
            heading = Gtk.Label(label="Кэш Discord", xalign=0)
            heading.add_css_class("title-2")
            page.append(heading)
            page.append(Gtk.Label(label="Сначала закройте Discord. Проверяются native Stable/PTB/Canary/Development, Flatpak Stable и Snap Stable в поддерживаемых путях.\nОчищаются только Cache, Code Cache и GPUCache выбранного профиля. Токены, Cookies и настройки не удаляются.\nRoot не используется; чужие процессы не завершаются. Symlink, hardlink, вложенные mountpoints и неполная проверка процессов блокируют очистку.", wrap=True, xalign=0))
            self.button(page, "Проверить профили и кэш Discord", lambda: self.run_operation(self.backend.scan_discord, action="scan-discord"))
            self.discord_choices = []
            self.discord_instance = Gtk.DropDown(model=Gtk.StringList.new([]))
            self.discord_instance.connect("notify::selected", lambda *_: self.update_discord_choice())
            page.append(self.discord_instance)
            self.discord_info = Gtk.Label(wrap=True, xalign=0, selectable=True)
            page.append(self.discord_info)
            self.discord_clean = self.button(page, "Очистить выбранный кэш…", self.clean_discord)

            page = self.page(stack, "tester", "Тестировщик")
            page.append(Gtk.Label(label="Стандартный тип: HTTP/TLS1.2/TLS1.3-пробы и ping для целей из utils/targets.txt.\nBaseline выполняется без root и не трогает сервис. Уже работающий zapret остаётся включён: это замер текущего соединения, не гарантированно чистый канал.\nЗапуск стратегий пока недоступен: runner установленного помощника ещё не подключён. В демо используются только имитации.\nПробы не доказывают работу видео, QUIC или голоса Discord. Рекомендация информационная и не меняет профиль автоматически.", wrap=True, xalign=0))
            self.tester_type_standard = Gtk.CheckButton(label="Стандартный: HTTP/TLS + ping", active=True)
            page.append(self.tester_type_standard)
            self.tester_type_dpi = Gtk.CheckButton(label="DPI TCP 16–20: POST + Range на один host", group=self.tester_type_standard)
            self.tester_type_dpi.connect("notify::active", lambda *_: self.update_tester_mode())
            page.append(self.tester_type_dpi)
            self.tester_host = Gtk.Entry(hexpand=True)
            self.tester_host.set_placeholder_text("Собственный host для DPI (пусто — публичный набор, скачивается по запросу)")
            self.tester_host.set_sensitive(False)
            page.append(self.tester_host)
            page.append(Gtk.Label(label="Стратегии (ничего не выбрано — baseline без изменений сервиса):", wrap=True, xalign=0))
            self.tester_checks_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            page.append(self.tester_checks_box)
            row = Gtk.Box(spacing=8)
            page.append(row)
            self.tester_start = self.button(row, "Запустить тестирование…", self.start_tester)
            self.tester_status = Gtk.Label(wrap=True, xalign=0, selectable=True)
            page.append(self.tester_status)
            self.tester_export = self.button(page, "Экспорт текстового отчёта…", self.choose_tester_export)
            self.tester_export.set_sensitive(False)
            self.tester_view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True,
                                            wrap_mode=Gtk.WrapMode.WORD_CHAR)
            self.tester_view.get_buffer().set_text("Тестирование ещё не выполнялось.")
            scroll = Gtk.ScrolledWindow(vexpand=True, min_content_height=300)
            scroll.set_child(self.tester_view)
            page.append(scroll)

            page = self.page(stack, "logs", "Журнал")
            self.button(page, "Загрузить последние сообщения", lambda: self.run_operation(self.backend.logs, self.show_logs, action="logs"))
            self.log_view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
            scroll = Gtk.ScrolledWindow(vexpand=True, min_content_height=250)
            scroll.set_child(self.log_view)
            page.append(scroll)
            page.append(Gtk.Label(label="Показаны только сообщения, доступные текущему пользователю.\nПустой журнал не означает отсутствие ошибок сервиса.", wrap=True, xalign=0))
            if args.tester:
                stack.set_visible_child_name("tester")
                if args.smoke_test:
                    assert stack.get_visible_child_name() == "tester"
            self.window.present()
            if args.smoke_test:
                GLib.timeout_add_seconds(30, self.smoke_watchdog)
            self.refresh()

        def smoke_watchdog(self):
            if not self.failed:
                print("GTK demo smoke: FAILED (watchdog timeout after 30s)")
                self.failed = True
            self.quit()
            return GLib.SOURCE_REMOVE

        def page(self, stack, name, title):
            scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
            for edge in ("top", "bottom", "start", "end"):
                getattr(box, "set_margin_" + edge)(20)
            scroll.set_child(box)
            stack.add_titled(scroll, name, title)
            return box

        def button(self, parent, title, action):
            button = Gtk.Button(label=title, halign=Gtk.Align.START)
            button.connect("clicked", lambda *_: action())
            parent.append(button)
            return button

        def close_requested(self, *_):
            if self.busy:
                self.toast.add_toast(Adw.Toast(title="Дождитесь завершения операции; авторизацию можно отменить в её диалоге"))
            return self.busy

        def run_operation(self, operation, callback=None, action="refresh"):
            if self.busy:
                return
            busy_text, success_text = operation_messages(action)
            self.busy = True
            self.pages.set_sensitive(False)
            if action == "tester-run":
                # Cancel must stay reachable while the tester operation runs.
                self.tester_cancel_event = threading.Event()
                self.tester_cancel.set_sensitive(True)
                if args.smoke_test:
                    assert self.tester_cancel.is_sensitive(), "cancel inherits disabled stack sensitivity"
            if self.current_toast is not None:
                self.current_toast.dismiss()
                self.current_toast = None
            self.error_banner.set_revealed(False)
            self.spinner.start()
            self.progress_label.set_text(busy_text)
            self.progress.set_reveal_child(True)
            def work():
                result, error, snapshot = None, None, None
                try:
                    result = operation()
                except Exception as problem:
                    error = str(problem)
                try:
                    snapshot = self.backend.snapshot()
                except Exception as problem:
                    error = (error + "\n" if error else "") + "Не удалось обновить состояние: " + str(problem)
                GLib.idle_add(self.finished, result, error, snapshot, callback, success_text)
            # Do not terminate a privileged transaction when the window closes.
            threading.Thread(target=work, daemon=False).start()

        def finished(self, result, error, snapshot, callback, success_text):
            self.busy = False
            self.spinner.stop()
            self.progress.set_reveal_child(False)
            self.pages.set_sensitive(True)
            self.tester_cancel.set_sensitive(False)
            self.tester_cancel_event = None
            if snapshot is not None:
                self.render(snapshot)
            if error:
                self.failed = True
                self.error_text = error
                self.error_banner.set_revealed(True)
            else:
                if callback:
                    callback(result)
                if success_text:
                    self.current_toast = Adw.Toast(title=success_text, timeout=4)
                    self.toast.add_toast(self.current_toast)
            if args.smoke_test:
                GLib.idle_add(self.smoke_next)
            return GLib.SOURCE_REMOVE

        def show_error_details(self):
            dialog = Adw.AlertDialog(heading="Подробности ошибки", body="Сообщение можно выделить и скопировать.")
            text = Gtk.TextView(editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD_CHAR)
            text.get_buffer().set_text(self.error_text)
            scroll = Gtk.ScrolledWindow(min_content_height=180, max_content_height=320)
            scroll.set_child(text)
            dialog.set_extra_child(scroll)
            dialog.add_response("close", "Закрыть")
            dialog.set_close_response("close")
            dialog.present(self.window)
            return dialog

        def refresh(self):
            self.run_operation(lambda: None)

        def render(self, state):
            self.state = state
            diagnostic_report = state.get("diagnostics")
            self.diagnostics_view.get_buffer().set_text(diagnostics_text(diagnostic_report))
            self.diagnostics_copy.set_sensitive(diagnostic_report is not None)
            self.diagnostics_export.set_sensitive(diagnostic_report is not None)
            tcp_supported = state.get("helper_ready") and state.get("tcp_timestamps_supported", False)
            tcp = state.get("tcp_timestamps")
            self.read_tcp.set_sensitive(bool(tcp_supported))
            self.enable_tcp.set_sensitive(bool(tcp_supported and tcp and not tcp.get("error") and tcp.get("value") == "0"))
            if not tcp_supported:
                tcp_text = "Нужен установленный доверенный помощник с поддержкой TCP timestamps. Обновление системной копии автоматически не выполняется."
            elif not tcp:
                tcp_text = "Сначала отдельно прочитайте параметр с авторизацией. Значение в старом отчёте не считается подтверждением."
            elif tcp.get("error") or tcp.get("value") is None:
                tcp_text = "TCP timestamps: неизвестно · " + str(tcp.get("error") or "нет значения")
            else:
                tcp_text = f"net.ipv4.tcp_timestamps={tcp['value']} · " + ("выключены" if tcp["value"] == "0" else "уже включены; изменение не требуется")
                tcp_text += "\nСнимок: " + str(tcp.get("checked_at", "время неизвестно"))
                tcp_text += "\nТолько текущая загрузка/namespace. После перезагрузки или внешнего применения sysctl значение может измениться."
            self.tcp_info.set_text(tcp_text)
            self.render_tester(state)
            self.render_discord()
            installed = state["installed"]
            ready = state["helper_ready"]
            self.status.set_text(service_state_title(state))
            self.detail.set_text(f"Состояние: {state['state']} · {state['detail']}" if installed else "Системная служба zapret не установлена. Нажмите «Установить системный сервис…» для установки.")
            if state.get("unit_error"):
                self.status.set_text("Состояние сервиса неизвестно")
                self.detail.set_text(state["unit_error"])
            self.read_service_status.set_sensitive(ready and state.get("status_supported", False))
            report = service_status_text(state.get("service_report"))
            if ready and not state.get("status_supported"):
                report += "\nУстановленный помощник не поддерживает расширенный статус. Требуется согласованное обновление системной копии."
            self.service_report.set_text(report)
            if installed and not ready:
                self.detail.set_text(self.detail.get_text() + "\nПомощник отсутствует или небезопасен. Обновите управляемую установку через install.py update; код из checkout не повышается до root.")
            self.start.set_visible(installed)
            self.stop.set_visible(installed)
            self.restart.set_visible(installed)
            self.autostart.set_visible(installed)
            self.service_note.set_visible(installed)
            self.service_sep.set_visible(installed)
            self.read_service_status.set_visible(installed)
            self.service_report.set_visible(installed)
            self.install_btn.set_visible(not installed)
            self.install_btn.set_sensitive(not self.busy)
            self.remove_btn.set_visible(installed)
            self.remove_btn.set_sensitive(installed and ready and state.get("remove_supported", True))
            self.start.set_sensitive(installed and state["state"] in ("inactive", "failed"))
            self.stop.set_sensitive(installed and state["active"])
            self.restart.set_sensitive(installed and state["active"])
            self.autostart.set_label("Отключить автозапуск…" if state["enabled"] else "Включить автозапуск…")
            for button in (self.autostart, self.load, self.load_settings):
                button.set_sensitive(installed and ready)
            config = state["config"]
            index = profile_index(state["profiles"], config)
            # Gtk.DropDown auto-selects the first entry in a nonempty model,
            # even when asked to select INVALID_LIST_POSITION.
            self.profiles.set_model(Gtk.StringList.new(state["profiles"] if index is not None else []))
            self.profiles.set_selected(index if index is not None else Gtk.INVALID_LIST_POSITION)
            self.profiles.set_sensitive(index is not None)
            if config:
                profile = config["config"]["strategy"]
                self.profile_info.set_text("Текущий профиль: " + profile)
            else:
                self.profile_info.set_text("Настройки ещё не прочитаны")
            self.select.set_sensitive(installed and ready and index is not None)
            game_supported = bool(config and "game-filter-ranges-v1" in config.get("capabilities", []))
            for widget in (self.game_mode, self.game_tcp, self.game_udp, self.save_game):
                widget.set_sensitive(installed and ready and game_supported)
            self.game_mode.set_model(Gtk.StringList.new(GAME_LABELS if config else []))
            if config:
                mode, tcp_ports, udp_ports = game_filter_values(config["config"])
                self.game_mode.set_selected(GAME_MODES.index(mode))
                self.game_tcp.set_text(tcp_ports)
                self.game_udp.set_text(udp_ports)
                self.game_info.set_text("Сохранённый режим: " + GAME_LABELS[GAME_MODES.index(mode)] if game_supported
                                        else "Установленный помощник не поддерживает новые настройки. Требуется обновление системной копии; автоматически оно не выполняется.")
            else:
                self.game_mode.set_selected(Gtk.INVALID_LIST_POSITION)
                self.game_tcp.set_text("")
                self.game_udp.set_text("")
                self.game_info.set_text("Сначала прочитайте настройки. Изменения не применяются автоматически.")
            ipset_supported = bool(config and "ipset-mode-v1" in config.get("capabilities", []))
            self.ipset_mode.set_model(Gtk.StringList.new(IPSET_LABELS if config else []))
            self.ipset_mode.set_sensitive(installed and ready and ipset_supported)
            info = config.get("ipset", {}) if config else {}
            current_mode = info.get("effective_mode")
            self.ipset_mode.set_selected(IPSET_MODES.index(current_mode) if current_mode in IPSET_MODES and config
                                         else 0 if config else Gtk.INVALID_LIST_POSITION)
            if not config:
                self.ipset_info.set_text("Сначала прочитайте настройки.")
            elif not ipset_supported:
                self.ipset_info.set_text("Установленный помощник не поддерживает режимы IPSet. Обновление системной копии автоматически не выполняется.")
            else:
                text = "Сохранённый режим: " + (current_mode or "неизвестно")
                if info.get("configured_mode") == "legacy":
                    text += " (по существующему файлу)"
                if info.get("loaded_available"):
                    text += f"\nЗагруженный набор: {info['loaded_entries']} записей\n{info['loaded_source']}\nSHA-256: {info['loaded_sha256']}"
                if info.get("warning"):
                    text += "\n" + info["warning"]
                self.ipset_info.set_text(text)
            ipset_update_supported = bool(config and "ipset-update-v1" in config.get("capabilities", []))
            self.ipset_update.set_sensitive(installed and ready and ipset_update_supported)
            self.update_ipset_button()
            fakes_supported = bool(config and "active-fakes-v1" in config.get("capabilities", []))
            self.fake_choices = {"discord": [None], "gameudp": [None]}
            fakes = config.get("fakes", {}) if config else {}
            usage = config.get("fakes_usage", {}) if config else {}
            for kind, dropdown in (("discord", self.fake_discord), ("gameudp", self.fake_gameudp)):
                labels, choices = ["По умолчанию (из стратегии)"], [None]
                info = fakes.get(kind, {}) if isinstance(fakes, dict) else {}
                for item in info.get("available", []):
                    labels.append(f"{item['name']} · {item['size']} Б · {item['sha256'][:12]}…")
                    choices.append(item["sha256"])
                self.fake_choices[kind] = choices
                dropdown.set_model(Gtk.StringList.new(labels if config else []))
                dropdown.set_sensitive(installed and ready and fakes_supported)
                override = info.get("override_sha256") if info.get("configured") else None
                dropdown.set_selected(choices.index(override) if override in choices
                                      else 0 if config else Gtk.INVALID_LIST_POSITION)
            if not config:
                self.fakes_info.set_text("Сначала прочитайте настройки.")
            elif not fakes_supported:
                self.fakes_info.set_text("Установленный помощник не поддерживает выбор активных fakes. Обновление системной копии автоматически не выполняется.")
            else:
                def describe_fakes(kind):
                    info = fakes.get(kind, {})
                    text = f"{'Замена: ' + str(info.get('matched_name')) if info.get('configured') else 'Замены нет'}"
                    count = usage.get(kind, 0)
                    if not count:
                        text += " · текущая стратегия не использует этот fake"
                    if info.get("warning"):
                        text += "\n" + info["warning"]
                    return text
                self.fakes_info.set_text("Discord UDP: " + describe_fakes("discord")
                                         + "\nGameFilter UDP: " + describe_fakes("gameudp"))
            self.update_fakes_button()
            hosts_supported = bool(config and "hosts-update-v1" in config.get("capabilities", []))
            self.hosts_update.set_sensitive(installed and ready and hosts_supported)
            text = self.describe_hosts(state.get("hosts", {}))
            if not config:
                text += "\nСначала прочитайте настройки, чтобы проверить поддержку обновления hosts."
            elif not hosts_supported:
                text += "\nУстановленный помощник не поддерживает обновление hosts. Обновление системной копии автоматически не выполняется."
            self.hosts_info.set_text(text)
            pending = state["pending"]
            self.apply.set_sensitive(installed and ready and bool(pending))
            text = "Подготовленного пакета нет."
            if pending:
                text = f"Подготовлено, но не применено: {pending.get('tag') or pending.get('revision')}\nSHA-256: {pending.get('digest')}"
            if state["update_error"]:
                text += "\n" + state["update_error"]
            self.update_info.set_text(text)
            versions = state.get("versions", {})
            self.version_info.set_text(version_text(versions))
            for link, key in ((self.current_data_link, "current"), (self.checked_data_link, "checked")):
                target = versions.get(key, {})
                uri = target.get("release_url") or target.get("commit_url")
                link.set_visible(bool(uri))
                link.set_uri(uri or self.flowseal_source.get_uri())
            check = state.get("auto_check", {})
            enabled = check.get("enabled")
            text = ("Автоматическая проверка: включена" if enabled is True else
                    "Автоматическая проверка: выключена" if enabled is False else
                    "Автоматическая проверка: состояние неизвестно")
            if check.get("active") and enabled is False:
                text += "\nТаймер запущен вручную, но не включён при входе."
            if enabled is True and check.get("active") is False:
                text += "\nТаймер включён при входе, но сейчас не запущен."
            if check.get("next_check") and check.get("active"):
                text += "\nСледующая проверка: " + check["next_check"]
            last = check.get("last_check")
            if last:
                text += "\nПоследняя проверка: " + str(last.get("checked_at", "время неизвестно"))
                if last.get("status") == "error":
                    text += "\nОшибка: " + str(last.get("message", "неизвестная ошибка"))
                else:
                    if versions.get("relation") == "unknown":
                        text += "\nВерсия Flowseal найдена; текущая установленная ревизия неизвестна."
                    else:
                        text += "\n" + ("Ревизии данных Flowseal различаются" if versions["relation"] == "different" else "Данные Flowseal совпадают с установленными")
                    text += "\nВерсия: " + str(last.get("tag") or last.get("revision") or "неизвестно")
            else:
                text += "\nСохранённого результата проверки пока нет."
            if check.get("preparation_enabled"):
                text += "\nОтдельно включён старый таймер ПОДГОТОВКИ стратегий. Этот переключатель его не меняет; автоматического применения нет."
            if check.get("execution_error"):
                text += "\n" + check["execution_error"]
            if check.get("error"):
                text += "\n" + check["error"]
            self.auto_check_info.set_text(text)
            self.auto_check_toggle.set_sensitive(enabled is not None and not check.get("error"))
            self.auto_check_toggle.set_label("Выключить автоматическую проверку…" if enabled else "Включить автоматическую проверку…")

        def confirm(self, title, body, operation, action, callback=None):
            if self.busy:
                return
            dialog = Adw.AlertDialog(heading=title, body=body)
            dialog.add_response("cancel", "Отмена")
            dialog.add_response("apply", "Продолжить")
            dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)
            dialog.set_default_response("cancel")
            dialog.set_close_response("cancel")
            dialog.connect("response", lambda _, response: self.run_operation(operation, callback, action=action) if response == "apply" else None)
            dialog.present(self.window)

        def service(self, action):
            titles = {"start": "Запуск сервиса", "stop": "Остановка сервиса", "restart": "Перезапуск сервиса"}
            self.confirm(titles[action], "Будет изменено состояние zapret и его правил firewall. Может потребоваться авторизация администратора.", lambda: self.backend.service_action(action), action=action)

        def toggle_autostart(self):
            enabled = not self.state.get("enabled", False)
            self.confirm("Автозапуск", "Изменить запуск сервиса при загрузке системы? Текущее состояние сервиса не изменится.", lambda: self.backend.set_autostart(enabled), action="set-autostart")

        def install_service_action(self):
            if self.busy or self.state.get("installed"):
                return
            dialog = Adw.AlertDialog(heading="Установка системного сервиса",
                                     body="Будет выполнена установка в /opt/zapret-discord-youtube и создан systemd-сервис.\nМожет потребоваться авторизация администратора.")
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            box.append(Gtk.Label(label="Стратегия по умолчанию:", xalign=0))
            profiles = self.state.get("profiles", [])
            combo = Gtk.DropDown(model=Gtk.StringList.new(profiles))
            if profiles:
                idx = profiles.index("general_alt12.bat") if "general_alt12.bat" in profiles else 0
                combo.set_selected(idx)
            box.append(combo)
            start_check = Gtk.CheckButton(label="Запустить и включить автозапуск сразу после установки", active=True)
            box.append(start_check)
            dialog.set_extra_child(box)
            dialog.add_response("cancel", "Отмена")
            dialog.add_response("install", "Установить")
            dialog.set_response_appearance("install", Adw.ResponseAppearance.SUGGESTED)
            dialog.set_default_response("cancel")
            dialog.set_close_response("cancel")
            def on_response(source, response):
                if response == "install":
                    idx = combo.get_selected()
                    chosen = profiles[idx] if idx < len(profiles) else None
                    start_now = start_check.get_active()
                    self.run_operation(lambda: self.backend.install_service(chosen, start=start_now), action="install-service")
            dialog.connect("response", on_response)
            dialog.present(self.window)
            return dialog

        def remove_service_action(self):
            if self.busy or not self.state.get("installed"):
                return
            dialog = Adw.AlertDialog(heading="Удаление системного сервиса",
                                     body="Системный сервис zapret_discord_youtube будет остановлен, отключён из автозапуска и удалён из /opt/zapret-discord-youtube. Приложение и помощник сохранятся для повторной установки.\n\nМожет потребоваться авторизация администратора.")
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            purge_check = Gtk.CheckButton(label="Удалить также пользовательские настройки (/etc/zapret-discord-youtube)", active=False)
            box.append(purge_check)
            dialog.set_extra_child(box)
            dialog.add_response("cancel", "Отмена")
            dialog.add_response("remove", "Удалить")
            dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_default_response("cancel")
            dialog.set_close_response("cancel")
            def on_response(source, response):
                if response == "remove":
                    purge = purge_check.get_active()
                    self.run_operation(lambda: self.backend.remove_service(purge=purge), action="remove-service")
            dialog.connect("response", on_response)
            dialog.present(self.window)
            return dialog

        def toggle_auto_check(self):
            check = self.state.get("auto_check", {})
            if check.get("enabled") is None or check.get("error"):
                return
            enabled = not check["enabled"]
            body = ("Включить ежедневную проверку Flowseal в пользовательском systemd? Может сразу выполниться пропущенная проверка. Скачивание стратегий и применение не выполняются."
                    if enabled else "Отключить ежедневную проверку? Уже начавшаяся проверка может завершиться; сервис zapret и отдельный таймер подготовки не изменяются.")
            self.confirm("Автоматическая проверка", body,
                         lambda: self.backend.set_auto_check(enabled), action="set-auto-check")

        def select_profile(self):
            item = self.profiles.get_selected_item()
            config = self.state.get("config")
            if item is not None and config:
                strategy = item.get_string()
                self.confirm("Смена стратегии", f"Выбран {strategy}. Работающий сервис будет перезапущен; при ошибке восстановятся прежние настройки.", lambda: self.backend.select_profile(strategy, config["sha256"]), action="select-profile")

        def set_game_filter(self):
            config = self.state.get("config")
            index = self.game_mode.get_selected()
            if not config or "game-filter-ranges-v1" not in config.get("capabilities", []) or index >= len(GAME_MODES):
                return
            tcp_ports, udp_ports = self.game_tcp.get_text().strip(), self.game_udp.get_text().strip()
            try:
                validate_game_ports(tcp_ports)
                validate_game_ports(udp_ports)
            except ValueError as error:
                self.error_text = str(error)
                self.error_banner.set_revealed(True)
                return
            mode = GAME_MODES[index]
            self.confirm("Настройки Game Filter", f"Режим: {GAME_LABELS[index]}\nTCP: {tcp_ports}\nUDP: {udp_ports}\n\nПрофиль стратегии не меняется. Работающий сервис будет перезапущен; остановленный останется остановленным.",
                         lambda: self.backend.set_game_filter(mode, tcp_ports, udp_ports, config["sha256"]), action="set-game-filter")

        def update_ipset_button(self):
            if not hasattr(self, "save_ipset"):
                return
            config = self.state.get("config")
            index = self.ipset_mode.get_selected()
            mode = IPSET_MODES[index] if index < len(IPSET_MODES) else None
            supported = bool(config and "ipset-mode-v1" in config.get("capabilities", []))
            loaded = bool(config and config.get("ipset", {}).get("loaded_available"))
            self.save_ipset.set_sensitive(bool(self.state.get("installed") and self.state.get("helper_ready")
                                              and supported and mode and (mode != "loaded" or loaded)))

        def set_ipset_mode(self):
            config = self.state.get("config")
            index = self.ipset_mode.get_selected()
            if not config or "ipset-mode-v1" not in config.get("capabilities", []) or index >= len(IPSET_MODES):
                return
            mode = IPSET_MODES[index]
            if mode is None:
                return
            token = None
            details = ""
            if mode == "loaded":
                info = config.get("ipset", {})
                if not info.get("loaded_available"):
                    return
                token = info["loaded_sha256"]
                details = f"\nНабор: {info['loaded_source']}\nSHA-256: {token}"
            self.confirm("Режим IPSet", f"{IPSET_LABELS[index]}{details}\n\nИсходные списки не перезаписываются. Работающий сервис будет перезапущен, остановленный не запускается.",
                         lambda: self.backend.set_ipset_mode(mode, config["sha256"], token), action="set-ipset-mode")

        def update_ipset(self):
            config = self.state.get("config")
            if not config or "ipset-update-v1" not in config.get("capabilities", []):
                return
            self.run_operation(self.backend.fetch_ipset, callback=self.offer_ipset_update, action="fetch-ipset")

        def offer_ipset_update(self, result):
            info = (self.state.get("config") or {}).get("ipset", {})
            body = (f"Записей: {result['entries']} · размер: {result['size']} байт\n"
                    f"SHA-256: {result['sha256']}\n"
                    f"Источник: Flowseal .service/ipset-service.txt\n\n")
            if info.get("loaded_available"):
                body += (f"Текущий загруженный набор: {info['loaded_entries']} записей\n"
                         f"SHA-256: {info['loaded_sha256']}\n\n")
            if info.get("loaded_sha256") == result["sha256"]:
                body += "Скачанный список совпадает с текущим загруженным набором.\n"
            body += ("Файл будет записан в постоянные данные (user-lists/ipset-all.txt).\n"
                     "Режим IPSet, списки доменов и пользовательские исключения не изменяются.\n"
                     "Работающий сервис будет перезапущен, остановленный не запускается.")
            self.confirm("Обновление списка IPSet", body,
                         lambda: self.backend.update_ipset(result["staged"], result["sha256"],
                                                           self.state["config"]["sha256"]),
                         action="update-ipset")

        def update_fakes_button(self):
            if not hasattr(self, "save_fakes"):
                return
            config = self.state.get("config")
            supported = bool(config and "active-fakes-v1" in config.get("capabilities", []))
            changed = False
            for kind, dropdown in (("discord", self.fake_discord), ("gameudp", self.fake_gameudp)):
                index = dropdown.get_selected()
                choices = getattr(self, "fake_choices", {}).get(kind, [None])
                selected = choices[index] if index < len(choices) else None
                info = (config or {}).get("fakes", {}).get(kind, {})
                current = info.get("override_sha256") if info.get("configured") else None
                changed = changed or selected != current
            self.save_fakes.set_sensitive(bool(self.state.get("installed") and self.state.get("helper_ready")
                                               and supported and changed))

        def set_active_fakes(self):
            config = self.state.get("config")
            if not config or "active-fakes-v1" not in config.get("capabilities", []):
                return
            selection, details = {}, ""
            for kind, title, dropdown in (("discord", "Discord UDP", self.fake_discord),
                                          ("gameudp", "GameFilter UDP", self.fake_gameudp)):
                index = dropdown.get_selected()
                choices = getattr(self, "fake_choices", {}).get(kind, [None])
                if index >= len(choices):
                    return
                selection[kind] = choices[index]
                if selection[kind] is not None:
                    item = next((entry for entry in config.get("fakes", {}).get(kind, {}).get("available", [])
                                 if entry["sha256"] == selection[kind]), None)
                    if item is None:
                        return
                    details += f"\n{title}: {item['name']}\nSHA-256: {item['sha256']}"
                else:
                    details += f"\n{title}: по умолчанию"
            self.confirm("Активные fakes", f"{details}\n\nВыбранные файлы копируются из релиза в постоянные данные; исходные .bin не изменяются.\nРаботающий сервис будет перезапущен, остановленный не запускается.",
                         lambda: self.backend.set_active_fakes(selection["discord"], selection["gameudp"], config["sha256"]),
                         action="set-active-fakes")

        def describe_hosts(self, info):
            if not info or not info.get("readable"):
                return info.get("error") or "Не удалось прочитать /etc/hosts."
            text = f"Файл /etc/hosts: {info.get('size', 0)} байт"
            if info.get("malformed"):
                text += "\nУправляемый блок повреждён: " + info["malformed"]
            elif info.get("present"):
                text += f"\nУправляемый блок: {info.get('entries', 0)} записей"
            else:
                text += "\nУправляемый блок не найден; записи будут добавлены в конец файла."
            if info.get("sha256"):
                text += "\nSHA-256: " + info["sha256"]
            if info.get("youtube"):
                text += "\nВ файле вне управляемого блока есть записи YouTube. Они не изменяются; проверьте их вручную."
            return text

        def update_hosts(self):
            config = self.state.get("config")
            if not config or "hosts-update-v1" not in config.get("capabilities", []):
                return
            self.run_operation(self.backend.fetch_hosts, callback=self.offer_hosts_update, action="fetch-hosts")

        def offer_hosts_update(self, result):
            preview = result.get("preview") or {}
            lines = [f"Записей в новом блоке: {preview.get('entries', result.get('entries'))} · размер: {result.get('size')} байт",
                     f"SHA-256: {result.get('sha256')}",
                     "Источник: Flowseal .service/hosts", ""]
            if preview.get("present"):
                lines.append(f"Текущий блок: {preview.get('current_entries', 0)} записей")
            else:
                lines.append("Управляемого блока сейчас нет — он будет добавлен в конец /etc/hosts.")
            if preview.get("changed"):
                lines.append(f"Добавится строк: {preview.get('added', 0)}, удалится: {preview.get('removed', 0)}")
            else:
                lines.append("Содержимое уже совпадает; файл не изменится.")
            conflicts = preview.get("conflicts") or []
            if conflicts:
                lines.append("\nВнимание: эти имена уже связаны с другими адресами вне блока:")
                lines += ["· " + item for item in conflicts[:10]]
                if len(conflicts) > 10:
                    lines.append(f"… и ещё {len(conflicts) - 10}")
            if preview.get("youtube"):
                lines.append("\nВ /etc/hosts уже есть записи YouTube вне блока; они не изменяются.")
            lines.append("\nИзменяется только управляемый блок; остальные строки, владелец и права файла сохраняются. Перед записью создаётся резервная копия. Сервис не перезапускается.")
            dialog = Adw.AlertDialog(heading="Обновление hosts", body="\n".join(lines))
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            label = Gtk.Label(label="Различия управляемого блока", xalign=0)
            label.add_css_class("dim-label")
            box.append(label)
            text = Gtk.TextView(editable=False, cursor_visible=False, monospace=True,
                                wrap_mode=Gtk.WrapMode.WORD_CHAR)
            text.get_buffer().set_text("\n".join(preview.get("diff") or []) or "Различий нет.")
            scroll = Gtk.ScrolledWindow(min_content_height=180, max_content_height=320)
            scroll.set_child(text)
            box.append(scroll)
            dialog.set_extra_child(box)
            dialog.add_response("cancel", "Отмена")
            dialog.add_response("export", "Экспортировать…")
            dialog.add_response("apply", "Применить")
            dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)
            dialog.set_default_response("cancel")
            dialog.set_close_response("cancel")
            def response(source, choice):
                if choice == "export":
                    self.choose_hosts_export(result)
                elif choice == "apply":
                    token = (result.get("hosts") or {}).get("sha256")
                    if token:
                        self.run_operation(lambda: self.backend.update_hosts(
                            result["staged"], result["sha256"], token), action="update-hosts")
            dialog.connect("response", response)
            dialog.present(self.window)
            return dialog

        def choose_hosts_export(self, result):
            dialog = Gtk.FileDialog(title="Сохранить скачанный hosts", initial_name="hosts-service.txt")
            def saved(source, response):
                try:
                    target = source.save_finish(response)
                except GLib.Error as error:
                    if not error.matches(GLib.quark_from_string("gtk-dialog-error-quark"),
                                         Gtk.DialogError.DISMISSED):
                        self.error_text = str(error)
                        self.error_banner.set_revealed(True)
                    return
                path = target.get_path()
                if path:
                    self.run_operation(lambda: self.backend.export_hosts(
                        result["staged"], result["sha256"], path), action="export-hosts")
            dialog.save(self.window, None, saved)

        def copy_diagnostics(self):
            report = self.state.get("diagnostics")
            if report is not None:
                self.window.get_clipboard().set(diagnostics_text(report))
                self.toast.add_toast(Adw.Toast(title="Отчёт скопирован. Проверьте его перед передачей другим."))

        def enable_tcp_timestamps(self):
            tcp = self.state.get("tcp_timestamps")
            if not self.state.get("tcp_timestamps_supported") or not tcp or tcp.get("error") or tcp.get("value") != "0":
                return
            expected = tcp["value"]
            self.confirm("Включить TCP timestamps?",
                         "Будет изменён только net.ipv4.tcp_timestamps: 0 → 1 в текущем ядре/network namespace.\n\nЭто влияет на системный TCP, не только zapret, и не гарантирует решение проблемы доступа. Постоянный файл настройки не создаётся, сервис не перезапускается.\n\nПри обнаруженном изменении после просмотра запись отменяется. При ошибке предпринимается проверяемое восстановление; при неизвестном результате или чужом значении слепой записи не будет. Может потребоваться авторизация администратора.",
                         lambda: self.backend.enable_tcp_timestamps(expected), action="enable-tcp-timestamps")

        def choose_diagnostics_export(self):
            if self.state.get("diagnostics") is None:
                return
            dialog = Gtk.FileDialog(title="Сохранить отчёт с локальными сетевыми сведениями", initial_name="zapret-diagnostics.json")
            def saved(source, response):
                try:
                    target = source.save_finish(response)
                except GLib.Error as error:
                    if not error.matches(GLib.quark_from_string("gtk-dialog-error-quark"), Gtk.DialogError.DISMISSED):
                        self.error_text = str(error)
                        self.error_banner.set_revealed(True)
                    return
                path = target.get_path()
                if path:
                    self.run_operation(lambda: self.backend.export_diagnostics(path), action="export-diagnostics")
            dialog.save(self.window, None, saved)

        def update_tester_mode(self):
            self.tester_host.set_sensitive(self.tester_type_dpi.get_active())

        def render_tester(self, state):
            tester = state.get("tester") or {}
            previous = {name: check.get_active() for name, check in self.tester_checks}
            child = self.tester_checks_box.get_first_child()
            while child is not None:
                following = child.get_next_sibling()
                self.tester_checks_box.remove(child)
                child = following
            self.tester_checks = []
            for name in tester.get("strategies") or []:
                check = Gtk.CheckButton(label=name, active=previous.get(name, False))
                self.tester_checks_box.append(check)
                self.tester_checks.append((name, check))
            if not self.tester_checks:
                self.tester_checks_box.append(Gtk.Label(label="Стратегии не найдены; доступен только baseline.", wrap=True, xalign=0))
            self.tester_export.set_sensitive(bool(state.get("tester_report_summary")))

        def start_tester(self):
            if self.busy:
                return
            dpi = self.tester_type_dpi.get_active()
            names = [name for name, check in self.tester_checks if check.get_active()]
            host = self.tester_host.get_text().strip() or None
            if dpi:
                body = "DPI-пробы: POST с Range 0-65535 и короткими таймаутами" + (f" на host {host}." if host
                       else " на цели публичного набора (hyperion-cs.github.io); набор скачивается по этому нажатию и только на время теста.")
                body += "\nИзменений сервиса, firewall и настроек нет; пробы выполняются от вашего пользователя."
            elif names:
                body = ("Перед пробами текущий сервис zapret будет остановлен, каждая выбранная стратегия применяется по очереди, "
                        "после каждой выполняются пробы, затем прежнее состояние восстанавливается — в том числе при ошибке запуска.\n"
                        "Может потребоваться авторизация администратора. Конфиг не изменяется. Рекомендация информационная и не применяется автоматически.")
            else:
                body = "Baseline: пробы без стратегий. Сервис, firewall и настройки не изменяются, root не нужен."
            if names and not self.state.get("tester_supported"):
                body = "Запуск стратегий пока недоступен: runner установленного помощника ещё не подключён. Снимите выбор стратегий для baseline."
                dialog = Adw.AlertDialog(heading="Тестирование стратегий недоступно", body=body)
                dialog.add_response("close", "Закрыть")
                dialog.present(self.window)
                return
            if names and dpi:
                body += "\nВыбранные стратегии требуют временного изменения сервиса и firewall с восстановлением; возможна авторизация."
            def run():
                return self.backend.tester_run("dpi" if dpi else "standard", names, custom_dpi_host=host,
                    cancel_event=self.tester_cancel_event, progress=self.tester_progress_event)
            self.confirm("Запустить тестирование?", body, run,
                action="tester-run", callback=self.show_tester_report)

        def cancel_tester(self):
            event = self.tester_cancel_event
            if event is not None:
                event.set()
                self.tester_status.set_text("Отмена запрошена: оставшиеся стратегии и пробы будут пропущены, состояние будет восстановлено.")

        def tester_progress_event(self, event):
            GLib.idle_add(self.update_tester_status, event)

        def update_tester_status(self, event):
            kind = event.get("event")
            if kind == "strategy":
                self.tester_status.set_text(f"Проверяется {event.get('index', 0) + 1}/{event.get('total')}: {event.get('name')}")
            elif kind == "probes":
                self.tester_status.set_text(f"Выполняются пробы: {event.get('name')} · целей: {event.get('count')}")
            elif kind == "done":
                self.tester_status.set_text("Тестирование завершено.")
            return GLib.SOURCE_REMOVE

        def show_tester_report(self, result):
            self.tester_view.get_buffer().set_text(tester_text(result))

        def choose_tester_export(self):
            if not self.state.get("tester_report_summary"):
                return
            dialog = Gtk.FileDialog(title="Сохранить текстовый отчёт тестирования", initial_name="zapret-tester-report.txt")
            def saved(source, response):
                try:
                    target = source.save_finish(response)
                except GLib.Error as error:
                    if not error.matches(GLib.quark_from_string("gtk-dialog-error-quark"), Gtk.DialogError.DISMISSED):
                        self.error_text = str(error)
                        self.error_banner.set_revealed(True)
                    return
                path = target.get_path()
                if path:
                    self.run_operation(lambda: self.backend.export_tester_report(path), action="export-tester")
            dialog.save(self.window, None, saved)

        def render_discord(self):
            index = self.discord_instance.get_selected()
            previous = self.discord_choices[index]["id"] if index < len(self.discord_choices) else None
            report = self.state.get("discord")
            self.discord_choices = report.get("instances", []) if report else []
            self.discord_instance.set_model(Gtk.StringList.new([item["label"] for item in self.discord_choices]))
            selected = next((index for index, item in enumerate(self.discord_choices) if item["id"] == previous), 0)
            self.discord_instance.set_selected(selected if self.discord_choices else Gtk.INVALID_LIST_POSITION)
            self.update_discord_choice()

        def update_discord_choice(self):
            if not hasattr(self, "discord_clean"):
                return
            report = self.state.get("discord")
            index = self.discord_instance.get_selected()
            self.discord_clean.set_sensitive(False)
            if not report:
                self.discord_info.set_text("Профили ещё не проверялись. Обнаружение и очистка выполняются только по нажатию.")
                return
            processes = report.get("processes", {})
            ready = processes.get("state") == "clear"
            warning = ("" if ready else "Закройте Discord/electron и проверьте заново. Очистка заблокирована: "
                       + ("обнаружены процессы " + str(processes.get("pids", [])) if processes.get("state") == "running" else "проверка процессов неполная") + ".\n")
            if index >= len(self.discord_choices):
                self.discord_info.set_text(warning + "Профилей в поддерживаемых путях не найдено. Ничего не создаётся и не удаляется.")
                return
            item = self.discord_choices[index]
            text = warning + item["path"]
            if item.get("error"):
                text += "\nОчистка недоступна: " + item["error"]
            else:
                text += f"\nФайлов: {item['files']} · логический размер: {item['bytes']} байт"
                for cache in item.get("caches", []):
                    text += f"\n{cache['path']} · {cache['files']} файлов · {cache['bytes']} байт"
                if not item["files"]:
                    text += "\nФайлов кэша для очистки нет."
                self.discord_clean.set_sensitive(ready and bool(item.get("token")) and item["files"] > 0)
            self.discord_info.set_text(text)

        def clean_discord(self):
            index = self.discord_instance.get_selected()
            report = self.state.get("discord")
            if not report or report.get("processes", {}).get("state") != "clear" or index >= len(self.discord_choices):
                return
            item = dict(self.discord_choices[index])
            if item.get("error") or not item.get("token") or not item["files"]:
                return
            paths = "\n".join(cache["path"] for cache in item["caches"])
            self.confirm("Очистка кэша Discord", f"{item['label']}\n{paths}\n\nФайлов: {item['files']} · логический размер: {item['bytes']} байт.\n\nDiscord должен быть закрыт. Удаляется только подтверждённый кэш; токены, Cookies и настройки сохраняются. Корзина не используется: уже удалённые файлы при ошибке не восстанавливаются. Снимок проверяется повторно; при позднем изменении дерева операция может прерваться с частичным результатом.",
                         lambda: self.backend.clean_discord(item["id"], item["token"]), action="clean-discord")

        def apply_update(self):
            pending = self.state.get("pending")
            if pending:
                approved = dict(pending)
                self.confirm("Применение стратегий", f"Пакет: {approved.get('tag') or approved.get('revision')}\nSHA-256: {approved.get('digest')}\n\nРаботающий сервис будет переключён на проверенный пакет. Конфиг и пользовательские списки сохранятся.", lambda: self.backend.apply_update(approved), action="apply")

        def show_update(self, result):
            # finished() already rendered the refreshed snapshot. Do not append
            # raw JSON or present a prepared package as an installed version.
            if result.get("status") == "prepared":
                self.update_info.set_text(self.update_info.get_text() + "\nПакет только подготовлен. Для применения нужно отдельное подтверждение.")

        def show_logs(self, result):
            self.log_view.get_buffer().set_text(result)

        def smoke_next(self):
            if self.failed:
                if self.smoke_expected_error:
                    try:
                        assert self.error_banner.get_revealed(), "error is hidden"
                        assert self.error_text == "Тестовая ошибка авторизации", "error details lost"
                        assert not self.progress.get_reveal_child(), "progress stays visible after error"
                        assert self.pages.get_sensitive(), "pages remain disabled after error"
                        assert self.current_toast is None, "success notification shown after error"
                        assert self.state["versions"]["running_app"]["version"] in self.version_info.get_text(), "application version missing"
                        assert self.state["versions"]["relation"] == "same", "data versions not refreshed after apply"
                        assert self.current_data_link.get_visible() and self.checked_data_link.get_visible(), "version links missing"
                        dialog = self.show_error_details()
                        dialog.close()
                        self.failed = False
                        assert self.state["service_report"]["process"]["state"] == "absent", "final service status incorrect"
                        assert self.state["diagnostics"]["checks"], "diagnostics missing"
                        assert self.diagnostics_copy.get_sensitive() and self.diagnostics_export.get_sensitive(), "diagnostics export disabled"
                        report_buffer = self.diagnostics_view.get_buffer()
                        report_text = report_buffer.get_text(report_buffer.get_start_iter(), report_buffer.get_end_iter(), False)
                        assert "[Неизвестно]" in report_text and "[Неприменимо]" in report_text, "diagnostic states hidden"
                        assert self.state["discord"]["instances"][0]["files"] == 0, "demo cache not cleaned"
                        assert not self.discord_clean.get_sensitive(), "empty cache can be cleaned again"
                        assert self.state["tcp_timestamps"]["value"] == "1", "demo timestamps not enabled"
                        assert not self.enable_tcp.get_sensitive(), "already enabled timestamps can be rewritten"
                        assert self.state["tester_report_summary"], "tester report missing from snapshot"
                        tester_buffer = self.tester_view.get_buffer()
                        tester_text_value = tester_buffer.get_text(tester_buffer.get_start_iter(), tester_buffer.get_end_iter(), False)
                        assert "Best strategy: baseline" in tester_text_value, "dpi tester best missing"
                        assert "Apache-2.0" in tester_text_value, "dpi license missing"
                        assert "CUSTOM (Пользовательский)" in tester_text_value, "custom dpi target missing"
                        assert self.tester_export.get_sensitive(), "tester export disabled"
                        starts = [call for call in self.backend.tester_calls if call[0] == "start"]
                        assert ("start", "demo_a.bat") in starts and ("start", "demo_b.bat") in starts, "strategies not started"
                        assert len([call for call in self.backend.tester_calls if call[0] == "stop"]) == 2, "strategies not stopped"
                        assert [call for call in self.backend.tester_calls if call[0] == "restore"], "state not restored"
                        assert self.state["tester"]["strategies"] == ["demo_a.bat", "demo_b.bat"], "tester strategy list missing"
                        assert self.tester_cancel.get_sensitive() is False, "cancel stays sensitive after run"
                        print("GTK demo smoke: PASS (34 operations, settings, versions, diagnostics, runtime timestamps, Discord cache, tester, service lifecycle, error details)")
                    except Exception as error:
                        print(f"GTK demo smoke: FAILED ({error})")
                self.quit()
                return GLib.SOURCE_REMOVE
            try:
                assert not self.progress.get_reveal_child(), "progress stays visible"
                assert self.pages.get_sensitive(), "pages remain disabled"
                success = operation_messages(self.smoke_last_action)[1]
                assert (self.current_toast.get_title() if self.current_toast else None) == success, f"unexpected notification for {self.smoke_last_action}"
                if self.smoke_last_action == "remove-service":
                    assert not self.state["installed"], "service still installed after remove"
                    assert self.install_btn.get_visible(), "install button hidden after remove"
                    assert not self.remove_btn.get_visible(), "remove button visible after remove"
                elif self.smoke_last_action == "install-service":
                    assert self.state["installed"], "service not installed after install"
                    assert not self.install_btn.get_visible(), "install button visible after install"
                    assert self.remove_btn.get_visible(), "remove button hidden after install"
                if self.smoke_index == 0:
                    unread = dict(self.state, config=None)
                    self.render(unread)
                    assert self.profiles.get_selected() == Gtk.INVALID_LIST_POSITION, "unread profile selected"
                    assert not self.profiles.get_sensitive(), "unread selector enabled"
                    assert not self.save_game.get_sensitive(), "unread game filter enabled"
                    assert not self.save_ipset.get_sensitive(), "unread IPSet enabled"
                    assert not self.ipset_update.get_sensitive(), "unread IPSet update enabled"
                    assert not self.save_fakes.get_sensitive(), "unread fakes enabled"
                    assert not self.hosts_update.get_sensitive(), "unread hosts update enabled"
                    self.render(self.backend.snapshot())
                    assert self.save_game.get_sensitive(), "demo game filter disabled"
                    assert self.ipset_update.get_sensitive(), "demo IPSet update disabled"
                    assert self.hosts_update.get_sensitive(), "demo hosts update disabled"
                    dialog = self.offer_hosts_update(self.backend.fetch_hosts())
                    dialog.close()
                    legacy = dict(self.state, config={"config": self.state["config"]["config"], "sha256": "0" * 64})
                    self.render(legacy)
                    assert not self.save_game.get_sensitive(), "old helper can edit new settings"
                    assert not self.save_ipset.get_sensitive(), "old helper can edit IPSet"
                    assert not self.ipset_update.get_sensitive(), "old helper can update IPSet"
                    assert not self.save_fakes.get_sensitive(), "old helper can edit fakes"
                    assert not self.hosts_update.get_sensitive(), "old helper can update hosts"
                    self.render(self.backend.snapshot())
            except Exception as error:
                self.failed = True
                print(f"GTK demo smoke: FAILED ({error})")
                self.quit()
                return GLib.SOURCE_REMOVE
            steps = [("start", lambda: self.backend.service_action("start")),
                     ("read-status", self.backend.read_status),
                     ("set-auto-check", lambda: self.backend.set_auto_check(True)),
                     ("set-auto-check", lambda: self.backend.set_auto_check(False)),
                     ("read-config", self.backend.load_config),
                     ("select-profile", lambda: self.backend.select_profile("general_alt.bat", "0" * 64)),
                     ("set-autostart", lambda: self.backend.set_autostart(True)),
                     ("set-game-filter", lambda: self.backend.set_game_filter("all", "2000-3000", "4000,5000-6000", self.state["config"]["sha256"])),
                     ("set-ipset-mode", lambda: self.backend.set_ipset_mode("none", self.state["config"]["sha256"])),
                     ("set-ipset-mode", lambda: self.backend.set_ipset_mode("any", self.state["config"]["sha256"])),
                     ("set-ipset-mode", lambda: self.backend.set_ipset_mode("loaded", self.state["config"]["sha256"], self.state["config"]["ipset"]["loaded_sha256"])),
                     ("fetch-ipset", self.backend.fetch_ipset),
                     ("update-ipset", lambda: self.backend.update_ipset("/demo-only/ipset-service.txt", "d" * 64, self.state["config"]["sha256"])),
                     ("fetch-hosts", self.backend.fetch_hosts),
                     ("update-hosts", lambda: self.backend.update_hosts("/demo-only/hosts-service.txt", self.backend.demo_hosts_sha, self.state["hosts"]["sha256"])),
                     ("set-active-fakes", lambda: self.backend.set_active_fakes("a" * 64, None, self.state["config"]["sha256"])),
                     ("set-active-fakes", lambda: self.backend.set_active_fakes(None, "b" * 64, self.state["config"]["sha256"])),
                     ("set-active-fakes", lambda: self.backend.set_active_fakes(None, None, self.state["config"]["sha256"])),
                     ("check", self.backend.check_update), ("prepare", self.backend.prepare_update),
                     ("apply", lambda: self.backend.apply_update(self.state["pending"])),
                     ("logs", self.backend.logs),
                     ("stop", lambda: self.backend.service_action("stop")),
                     ("read-status", self.backend.read_status),
                     ("read-tcp-timestamps", self.backend.read_tcp_timestamps),
                     ("enable-tcp-timestamps", lambda: self.backend.enable_tcp_timestamps(self.state["tcp_timestamps"]["value"])),
                     ("diagnostics", self.backend.diagnostics),
                     ("scan-discord", self.backend.scan_discord),
                     ("clean-discord", lambda: self.backend.clean_discord(self.state["discord"]["instances"][0]["id"],
                         self.state["discord"]["instances"][0]["token"])),
                     ("tester-run", lambda: self.backend.tester_run("standard", ["demo_a.bat", "demo_b.bat"],
                                                                    cancel_event=threading.Event(),
                                                                    progress=self.tester_progress_event)),
                     ("tester-run", lambda: self.backend.tester_run("dpi", [], custom_dpi_host="example.org")),
                     ("remove-service", lambda: self.backend.remove_service(purge=False)),
                     ("install-service", lambda: self.backend.install_service("general_alt.bat", start=False)),
                     ("read-status", self.backend.read_status)]
            if self.smoke_index < len(steps):
                action, step = steps[self.smoke_index]
                self.smoke_index += 1
                self.smoke_last_action = action
                callback = self.show_tester_report if action == "tester-run" else None
                self.run_operation(step, callback, action=action)
            else:
                if (self.state["active"] or self.state["auto_check"]["enabled"] or not self.state["auto_check"]["last_check"]
                        or self.state["config"]["config"]["strategy"] != "general_alt.bat" or not self.state["enabled"]
                        or self.game_tcp.get_text() != "2000-3000" or self.game_udp.get_text() != "4000,5000-6000"
                        or self.state["config"]["config"].get("ipset_mode") != "loaded"
                        or self.state["config"]["ipset"].get("loaded_sha256") != "d" * 64
                        or self.state["config"]["config"].get("fakediscord") != ""
                        or self.state["config"]["config"].get("fakegameudp") != ""
                        or self.state["config"]["fakes"]["discord"]["configured"]
                        or self.state["config"]["fakes"]["gameudp"]["configured"]
                        or not self.state["hosts"].get("present")
                        or self.state["hosts"].get("entries") != 3
                        or self.backend.hosts_data.count(b"# BEGIN zapret-discord-youtube managed hosts") != 1
                        or b"localhost" not in self.backend.hosts_data
                        or b"keep.example" not in self.backend.hosts_data):
                    self.failed = True
                    print("GTK demo smoke: FAILED (final state)")
                    self.quit()
                else:
                    self.smoke_expected_error = True
                    def fail():
                        raise RuntimeError("Тестовая ошибка авторизации")
                    self.run_operation(fail, action="read-config")
            return GLib.SOURCE_REMOVE

    app = Application()
    result = app.run([sys.argv[0]])
    return 1 if args.smoke_test and app.failed else result


if __name__ == "__main__":
    sys.exit(main())
