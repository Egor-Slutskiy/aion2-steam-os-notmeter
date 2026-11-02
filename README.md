# NotMeter на Linux / SteamOS (Steam Deck)

Запуск DPS-метра [NotMeter](https://github.com/Not4You-Dev/NotMeter-Releases) для Aion 2 через Proton.

## Почему не работает «из коробки»

NotMeter — Windows-приложение на .NET/WPF. Трафик игры он читает через Npcap, а это
драйвер ядра Windows: Wine и Proton его не загружают. Поэтому метр запускается, но
пакетов не видит.

## Как решено

В NotMeter есть встроенный механизм плагинов захвата. Под Wine, если задана переменная
`NOTMETER_PROTON_CAPTURE=1`, метр загружает плагин из папки `Plugins/Proton`. Этот
репозиторий содержит такой плагин и помощника для Linux:

```
 Aion 2 ──TCP──► сетевая карта
                     │  (сокет AF_PACKET, только TCP-порт игры)
                     ▼
        notmeter-capture.py      служба systemd, права: только CAP_NET_RAW
                     │  127.0.0.1:47380
                     ▼
 NotMeter.exe ◄── Plugins/Proton/NotMeter.Capture.Proton.dll      (внутри Proton)
```

* `linux/notmeter-capture.py` — помощник захвата. Нужен только Python 3, без
  дополнительных пакетов и libpcap. Фильтрует трафик в ядре (BPF) по порту игры, по
  умолчанию 13328. Слушает только `127.0.0.1` и обслуживает только вашего пользователя.
* `plugin/` — исходники плагина. Он передаёт метру пакеты так же, как это делает
  встроенный Npcap-провайдер.
* `dist/Plugins/Proton/NotMeter.Capture.Proton.dll` — собранный плагин.
* `install.sh` — установщик.

## Установка на Steam Deck

1. Перейдите в режим рабочего стола (Desktop Mode) и откройте Konsole.
2. Если пароль ещё не задан, задайте его: `passwd`.
3. Выполните:
   ```bash
   git clone https://github.com/egor-slutskiy/aion2-steam-os-notmeter.git
   cd aion2-steam-os-notmeter
   ./install.sh
   ```
   Скрипт скачает последний `NotMeter.exe` в `~/NotMeter`, положит туда плагин и
   установит службу `notmeter-capture`. Если `.exe` уже скачан, укажите путь к нему:
   `./install.sh ~/Downloads/NotMeter.exe`.
4. В Steam откройте Aion 2 → «Свойства» → «Общие» → «Параметры запуска» и вставьте:
   ```
   NOTMETER_PROTON_CAPTURE=1 PROTON_REMOTE_DEBUG_CMD="/home/deck/NotMeter/NotMeter.exe" %command%
   ```
   `PROTON_REMOTE_DEBUG_CMD` — штатная возможность Proton: запустить ещё одну программу
   вместе с игрой в том же префиксе. Поэтому метр видит процесс `Aion2` и его окно.
   Если игра запускается через лаунчер, добавленный в Steam как «сторонняя игра», эти
   параметры задаются у этого ярлыка.
5. Запустите игру. Метр откроется вместе с ней.

Проверить службу: `systemctl status notmeter-capture`, журнал: `journalctl -u notmeter-capture -f`.
Удалить: `./install.sh --uninstall`.

## Настройки

| Переменная (в параметрах запуска) | Что делает |
|---|---|
| `NOTMETER_GAME_PORT=0` | ловить все TCP-порты (например, если игра идёт через VPN или ускоритель на другом порту) |
| `NOTMETER_GAME_PORT=<n>` | другой порт сервера игры |
| `NOTMETER_HELPER_PORT=<n>` | другой порт помощника (тогда в службе нужен `--port <n>`) |

Параметры помощника: `python3 linux/notmeter-capture.py --help` (`--iface wlan0`,
`--game-port`, `--exclude`...).

## Что проверено, а что нет

Проверено (Ubuntu 24.04, NotMeter v1.0.315):
* помощник ловит входящие и исходящие пакеты, фильтр по порту работает, с одним
  `CAP_NET_RAW` всё работает, клиенты чужого пользователя отклоняются;
* настоящий загрузчик плагинов NotMeter (`ProtonCapturePlugin.LoadDirectory` из
  `NotMeter.exe`) принимает плагин, проверяет хеш и получает от него TCP-данные;
  плагин с неверным хешем отклоняется.

Не проверено: окно метра на настоящем Proton (проверить на Steam Deck пока было не на чем).
На системном Wine 9.0 из Ubuntu интерфейс WPF падает при отрисовке текста ещё до
начала захвата. Proton новее и поставляет свои шрифты, но если метр не открывается,
пришлите журнал Proton: добавьте `PROTON_LOG=1` в начало параметров запуска, журнал
появится в `~/steam-<appid>.log`.

В игровом режиме (Game Mode) gamescope может не показывать окно метра поверх игры.
В режиме рабочего стола оно отображается как обычное окно.

## Сборка плагина

Нужен .NET 8 SDK:
```bash
./plugin/build.sh            # скачает NotMeter.exe и соберёт dist/Plugins/Proton/*.dll
./plugin/build.sh path/NotMeter.exe
```
`tools/unbundle.py` достаёт `NotMeter.dll` из однофайлового `.exe`. Он нужен только
как ссылка при компиляции, в репозиторий не попадает.
