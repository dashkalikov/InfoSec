# Запуск проекта 3FA

`3FA` — графическое приложение. `WinNTL-11_6_0` — отдельная консольная утилита для генерации простых чисел и работы с RSA.

## Windows x64

Установите [MSYS2](https://www.msys2.org/) и откройте терминал **UCRT64**. Установите зависимости.

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-{gcc,cmake,ninja,qt6-base,opencv,openssl,sqlite3}
```

Из корня репозитория выполните в PowerShell. Замените путь к MSYS2, если он установлен в другой папке.

```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"
cmake -S 3FA -B 3FA/build-windows -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=C:/msys64/ucrt64
cmake --build 3FA/build-windows --parallel 4
.\3FA\run.bat
```

Для отдельной утилиты RSA используйте тот же терминал PowerShell.

```powershell
cmake -S WinNTL-11_6_0 -B WinNTL-11_6_0/build_cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=C:/msys64/ucrt64
cmake --build WinNTL-11_6_0/build_cmake --parallel 4
.\WinNTL-11_6_0\run.bat
```

## Ubuntu 24.04 x86-64

Установите зависимости один раз:

```bash
sudo apt update
sudo apt install --no-install-recommends build-essential cmake qt6-base-dev \
  libqt6sql6-sqlite libopencv-dev libssl-dev libsqlite3-dev libntl-dev
```

Откройте терминал в папке `InfoSec` и запустите нужный скрипт:

```bash
bash ./3FA/run.sh
bash ./WinNTL-11_6_0/run.sh
```

Первый запуск компилирует программу в `build-linux`. Повторный использует результаты предыдущей сборки и компилирует только изменения. Для окна `3FA` нужен графический сеанс Linux или WSL с WSLg. Для проверки лица нужны веб-камера и [модели](3FA/resources/face/README.md).

Тему можно переключить кнопкой в правом верхнем углу. 3FA запоминает выбор после закрытия.

Масштаб интерфейса меняется в диапазоне 75–200% через `Ctrl` + `+`, `Ctrl` + `-` или `Ctrl` с колёсиком. `Ctrl` + `0` возвращает 100%. После изменения на короткое время появляется панель с текущим процентом. Чтобы открыть её мышью, щёлкните правой кнопкой по заголовку окна и выберите «Масштаб». Выбранный масштаб сохраняется.

Форма входа подставляет почту последнего успешно вошедшего пользователя. Чтобы также запомнить пароль, отметьте флажок на форме и завершите вход. В Windows пароль защищается средствами системы. В настольном Linux для этой опции нужны системная связка ключей и `secret-tool` из пакета `libsecret-tools`. В стандартном Docker-запуске запоминается почта.

В разделе шифрования выберите «Кузнечик» слева или RSA справа. Подсветка перемещается к выбранному алгоритму. Кнопка создания сохраняет новые ключи в библиотеке аккаунта `3FA/rsa_keys/user-<id>`. Их можно снова выбрать после перезапуска. В Docker эта папка находится в томе `rsa-keys`.

RSA поддерживает пары до 65 536 бит. Генерация такого размера может занять значительное время. Она выполняется в фоне, а сохранённая пара доступна для повторного использования.

## Docker на Windows и Linux

Откройте папку `3FA` в терминале. На Windows сначала запустите Docker Desktop с Linux-контейнерами.

```sh
docker compose up -d --build --wait
```

Откройте [окно 3FA](http://127.0.0.1:6080/vnc.html?autoconnect=1&resize=scale) в браузере. Образ включает Qt, OpenCV, криптографические библиотеки и Python-зависимости. Контейнер хранит свою SQLite-базу, настройки, ключи и простые числа в Docker-томах. Для сохранения PDF выберите `/home/threefa/exports` внутри окна приложения. Скопировать файл на компьютер можно командой `docker compose cp app:/home/threefa/exports/имя.pdf .`.

Для восстановления пароля создайте `config/email.json` из `config/email.json.example` и укажите параметры SMTP. Скопируйте конфигурацию в том командой `docker compose cp config/email.json app:/opt/threefa/config/email.json` и перезапустите контейнер через `docker compose restart app`.

По умолчанию страницу с кодом можно открыть в браузере компьютера по кнопке **Копировать ссылку** на втором этапе. Для QR на телефоне создайте в папке `3FA` файл `.env` и укажите IPv4-адрес компьютера в локальной сети, например `THREEFA_LAN_IP=192.168.1.131`. Повторите `docker compose up -d --wait`. Телефон должен находиться в той же сети, а входящий TCP-порт `8765` должен быть доступен с телефона. Само окно 3FA доступно через браузер компьютера на порту `6080`.

Для проверки лица добавьте [модели](3FA/resources/face/README.md). На Linux передайте устройство камеры в контейнер. Для `/dev/video0` выполните:

```sh
THREEFA_CAMERA_GID=$(stat -c '%g' /dev/video0) \
  docker compose -f compose.yaml -f compose.camera.yaml up -d --build --wait
```

Для другого устройства укажите `THREEFA_CAMERA_DEVICE` и группу этого устройства. Для камеры Windows используйте обычный запуск через `run.bat`. В Docker Desktop вариант с камерой требует отдельного проброса USB/IP и появления устройства `/dev/video*` в Linux-среде Docker. [Docker Desktop и USB](https://docs.docker.com/desktop/troubleshoot-and-support/faqs/general/)

Остановить приложение можно командой `docker compose down`. Данные в томах сохраняются.

## Дополнительные функции Python

Для второго фактора нужен пакет `websockets` в том Python, который запускает `3FA`. В Windows выполните `python -m pip install websockets==15.0.1`. Телефон и компьютер должны быть в одной локальной сети. После ввода пароля отсканируйте QR камерой телефона и введите шестизначный код с открывшейся страницы.

Для операций с подписью PDF нужны Python 3.12 и пакеты из `3FA/requirements-runtime.txt`. Само окно входа открывается без установки этих пакетов.

В Windows установите [Python 3.12 x64](https://www.python.org/downloads/release/python-31210/). Из папки `3FA` выполните команды.

```powershell
py -3.12 -m venv venv_mediapipe
.\venv_mediapipe\Scripts\python.exe -m pip install -r requirements-runtime.txt
```

В Ubuntu 24.04 из папки `3FA` выполните:

```bash
sudo apt install python3-venv
python3 -m venv .venv-linux
.venv-linux/bin/python -m pip install -r requirements-runtime.txt
```

После установки запустите `3FA` через скрипт для своей платформы.

## Сторонние компоненты

В составе проекта используются NTL 11.6.0 и Material Symbols Rounded. Условия распространяемых компонентов находятся в [уведомлении NTL](NTL-COPYING.txt) и [лицензии Material Symbols](3FA/src/assets/material-symbols/LICENSE).
