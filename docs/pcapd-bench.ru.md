# Стенд pcapd на Android arm64

[English](pcapd-bench.md)

Для стенда этапа 3 нужен Python 3.10+ в Termux. Запускайте из каталога NetStat от
обычного пользователя Termux. Скрипт берёт его UID за эталон и запускает
официальный pcapd через `su`. Android `timeout` ограничивает работу pcapd
24 секундами и даёт ещё две секунды на завершение. Используется один интерфейс
с действующей конфигурацией сети.

## Запуск

Подготовьте официальный бинарник arm64-v8a в локальном игнорируемом каталоге.

```sh
git clone https://github.com/emanuele-f/pcapd-bin .superpowers/pcapd-bin
git -C .superpowers/pcapd-bin checkout --detach 6b54534635b53a0bcb62d8dbe788425a319b5611
```

Скрипт проверяет SHA-256
`4cc86aa41502882ec3a6ad4dab0d6c64aea3ee5d0efa23a7bdc208da646c3697`.
У ELF ABI Android 21 arm64, сборка выполнена NDK r20b. Репозиторий официальных
бинарников разрешает распространение с указанием авторства PCAPdroid. В исходном
файле указана GPL-3.0-or-later. [Бинарник и условия указания авторства](https://github.com/emanuele-f/pcapd-bin/tree/6b54534635b53a0bcb62d8dbe788425a319b5611) · [Исходник этой сборки](https://github.com/emanuele-f/PCAPdroid/blob/dbfaab61647893fc0b1f4ae9b15e857dcdcb8337/app/src/main/jni/pcapd/pcapd.c)

Loopback проверяет обмен с pcapd и экспорт. Клиент и локальный echo-сервер
имеют один UID Termux. Для проверки атрибуции между разными UID нужен другой стенд.

```sh
python tools/pcapd_bench.py loopback \
  --pcapd .superpowers/pcapd-bin/dist/arm64-v8a/libpcapd.so \
  --output .superpowers/pcapd-lo
```

Для текущей сети замените `wlan0` и `192.168.1.23` на имя активного
интерфейса и его IPv4. Команда посылает три TCP- и четыре UDP-запроса
A-записи `example.com` на `1.1.1.1:53`. В `--peer` можно указать другой
известный IPv4-резолвер. Для каждого прогона укажите новый выходной каталог.

```sh
python tools/pcapd_bench.py dns \
  --pcapd .superpowers/pcapd-bin/dist/arm64-v8a/libpcapd.so \
  --output .superpowers/pcapd-dns --interface wlan0 \
  --local-ip 192.168.1.23 --peer 1.1.1.1
```

## Результаты

- `probe.pcap` открывается в Wireshark. Входные записи используют 32-байтовый
  заголовок pcapd для arm64 little-endian и DLT_RAW 12. Выходной PCAP использует
  LINKTYPE_RAW 101 и микросекундные метки времени. pcapd сообщает длину захваченных байтов.
- Фильтр использует два IP и порты клиента и сервера, зарезервированные для
  каждого протокола до начала захвата. UDP-сокет закрывается сразу после обмена.
  Экспортёр сверяет адреса и порты ещё раз, а UDP сохраняет только при совпадении
  направления и всех байтов с отправленным запросом или проверенным ответом.
  Лимит записи — 1 500 пакетов и 2 МиБ данных пакетов.
- В `report.json` статус `correct` означает ожидаемый UID у всех сохранённых
  пакетов потока. `partial` означает смесь ожидаемого и неизвестного UID.
  `wrong` указывает на другой известный UID. `unknown` означает только
  неизвестные UID, `unseen` — отсутствие сохранённых пакетов потока.
- `udp_missing_messages` считает отправленные запросы и проверенные ответы,
  которых нет в записи. Для TCP указаны направления с данными. Счётчики
  потерь libpcap из журнала завершения находятся в `final_stats`.
  `dns_unavailable` означает, что проверенных ответов не получено. При
  `incomplete` причина запуска или ошибки интерфейса обычно видна в `pcapd.log`.

```sh
python -m unittest discover -s tools -p 'test_pcapd_bench.py'
```
