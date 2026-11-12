#!/usr/bin/env python3
"""Command for a desktop shortcut: stop only the systemd service, not autostart."""

import argparse
import subprocess
import sys


COMMAND = ["/usr/bin/systemctl", "stop", "zapret_discord_youtube.service"]


def notify(title, message):
    try:
        subprocess.run(["/usr/bin/notify-send", "--app-name=Zapret", title, message],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except OSError:
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="print the command without executing it")
    args = parser.parse_args(argv)
    if args.dry_run:
        print(" ".join(COMMAND))
        return 0

    # Use systemd's native polkit authorization. No password is stored and no
    # privileged shell, NOPASSWD rule or broad process kill is needed.
    try:
        result = subprocess.run(COMMAND, capture_output=True, text=True, check=False)
    except OSError as error:
        print(f"Не удалось вызвать systemctl: {error}", file=sys.stderr)
        notify("Zapret", "Не удалось вызвать systemctl.")
        return 127

    if result.returncode == 0:
        print("Сервис Zapret остановлен. Автозапуск не изменён.")
        notify("Zapret", "Сервис остановлен. Автозапуск не изменён.")
    else:
        print(result.stderr.strip() or "Не удалось остановить сервис Zapret.", file=sys.stderr)
        notify("Zapret", "Не удалось остановить сервис. Проверьте авторизацию и журнал systemd.")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
