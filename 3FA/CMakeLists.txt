# ============================================================================
# ФАЙЛ CMAKELISTS.TXT - КОНФИГУРАЦИЯ СБОРКИ ПРОЕКТА 3FA
# ============================================================================
# Этот файл содержит конфигурацию системы сборки CMake для проекта 3FA
# (Three-Factor Authentication). Определяет зависимости, пути включения,
# исходные файлы и настройки компиляции для всех компонентов проекта.
#
# КОМПОНЕНТЫ ПРОЕКТА:
# - Qt6 GUI приложение (основное приложение 3FA)
# - Алгоритмы криптографии: Stribog, Kuznechik, RSA-32768
# - Центр сертификации (minica)
# - Виджеты и UI компоненты
# ============================================================================

cmake_minimum_required(VERSION 3.16.0)          # минимальная версия CMake
project(3FA VERSION 0.1.0 LANGUAGES C CXX ASM)  # название проекта, версия, языки

# ============================================================================
# НАСТРОЙКИ СТАНДАРТА C++
# ============================================================================
# Устанавливаем стандарт C++17 для поддержки современных возможностей языка
# ============================================================================

set(CMAKE_CXX_STANDARD 17)                      # стандарт C++17
set(CMAKE_CXX_STANDARD_REQUIRED ON)             # требовать строгое соответствие стандарту

# ============================================================================
# ПОИСК И ПОДКЛЮЧЕНИЕ ВНЕШНИХ БИБЛИОТЕК
# ============================================================================
# Находим и подключаем необходимые библиотеки для работы приложения:
# - Qt6: GUI фреймворк для создания интерфейса
# - OpenCV: обработка изображений и видео для распознавания лиц
# - OpenSSL: криптографические операции
# ============================================================================

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Sql Network PrintSupport Concurrent)  # Qt6 компоненты
find_package(OpenCV REQUIRED COMPONENTS core imgproc imgcodecs dnn videoio objdetect)   # OpenCV компоненты
find_package(OpenSSL REQUIRED)                                                          # OpenSSL для криптографии

# ============================================================================
# НАСТРОЙКИ QT MOC (META-OBJECT COMPILER)
# ============================================================================
# Включаем автоматическую обработку Qt MOC для поддержки сигналов и слотов
# ============================================================================

set(CMAKE_AUTOMOC ON)                              # автоматическая обработка MOC

# ============================================================================
# КОНФИГУРАЦИЯ АЛГОРИТМА STRIBOG (ГОСТ Р 34.11-2012)
# ============================================================================
# Настройка путей включения и исходных файлов для алгоритма хеширования Stribog
# ============================================================================

# ДЕЙСТВИЕ 1: ПУТИ ВКЛЮЧЕНИЯ ДЛЯ STRIBOG
# Указываем директории, где находятся заголовочные файлы Stribog
include_directories(algorithms/Stribog)            # основная директория Stribog
include_directories(algorithms/Stribog/include)    # директория с константами
include_directories(algorithms/Stribog/standard)   # директория со стандартной реализацией

# ДЕЙСТВИЕ 2: ИСХОДНЫЕ ФАЙЛЫ STRIBOG
# Список исходных файлов для компиляции алгоритма Stribog
set(STRIBOG_SOURCES
    algorithms/Stribog/standard/stribog.cpp        # основная реализация алгоритма
    algorithms/Stribog/striboghash.cpp             # Qt-обертка над алгоритмом
)

# ============================================================================
# КОНФИГУРАЦИЯ АЛГОРИТМА KUZNECHIK (ГОСТ Р 34.12-2015)
# ============================================================================
# Настройка путей включения и исходных файлов для алгоритма шифрования Kuznechik
# ============================================================================

# ДЕЙСТВИЕ 1: ПУТИ ВКЛЮЧЕНИЯ ДЛЯ KUZNECHIK
# Указываем директории, где находятся заголовочные файлы Kuznechik
include_directories(algorithms/Kuznechik/include/constants)           # директория с константами

# ДЕЙСТВИЕ 2: ИСХОДНЫЕ ФАЙЛЫ KUZNECHIK
# Список исходных файлов для компиляции алгоритма Kuznechik
set(KUZNECHIK_SOURCES
    algorithms/Kuznechik/src/constants/kuznechik_constants.cpp        # основные криптографические операции
    algorithms/Kuznechik/src/constants/kuznechik_constants_data.cpp   # данные констант (S-box, L-вектор)
)

# ============================================================================
# КОНФИГУРАЦИЯ АЛГОРИТМА RSA-32768
# ============================================================================
# Настройка путей включения и исходных файлов для алгоритма RSA с ключами 32768 бит
# ============================================================================

# ДЕЙСТВИЕ 1: ПУТИ ВКЛЮЧЕНИЯ ДЛЯ RSA-32768 (NTL-based)
# Указываем директории, где находятся заголовочные файлы RSA-32768 и NTL
include_directories(algorithms/RSA-32768)                 # основная директория RSA-32768
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_path(NTL_INCLUDE_DIR NAMES NTL/ZZ.h)
    find_library(NTL_LIBRARY NAMES ntl)
    if(NOT NTL_INCLUDE_DIR OR NOT NTL_LIBRARY)
        message(FATAL_ERROR "NTL development files are required. On Ubuntu/Debian, install libntl-dev.")
    endif()
else()
    set(NTL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/algorithms/RSA-32768/include")
    set(NTL_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/algorithms/RSA-32768/lib/libntl.a")
endif()

# ДЕЙСТВИЕ 2: ПУТИ ВКЛЮЧЕНИЯ ДЛЯ ВИДЖЕТОВ И CA
# Указываем директории для пользовательских виджетов и центра сертификации
include_directories(widgets)                            # директория с виджетами
include_directories(ca)                                 # директория центра сертификации

# ДЕЙСТВИЕ 3: ИСХОДНЫЕ ФАЙЛЫ RSA-32768 (NTL-based)
# Список исходных файлов для компиляции алгоритма RSA-32768 на основе NTL
set(RSA_SOURCES
    algorithms/RSA-32768/PrimeFileManager.cpp           # управление файлами простых чисел
    algorithms/RSA-32768/RSAKeyManager.cpp              # управление RSA ключами
    algorithms/RSA-32768/RSACrypto.cpp                  # основные криптографические операции RSA
)

# RSA-32768 теперь использует NTL - GPU и ассемблерные оптимизации не нужны

# ============================================================================
# КОНФИГУРАЦИЯ ВИДЖЕТОВ
# ============================================================================
# Список исходных файлов пользовательских виджетов
# ============================================================================

set(WIDGETS_SOURCES
    widgets/materialcombobox.cpp                # Material Design ComboBox виджет
)

# ============================================================================
# ИСХОДНЫЕ ФАЙЛЫ ПРОЕКТА
# ============================================================================
# Список всех исходных файлов основного приложения 3FA
# ============================================================================

set(SOURCES
    src/apptheme.cpp
    src/appmessage.cpp
    main.cpp                                    # точка входа приложения
    src/mainwindow.cpp                          # главное окно приложения
    src/loginmemory.cpp
    src/facescanview.cpp
    src/authservice.cpp                         # сервис аутентификации
    src/database.cpp                            # работа с базой данных пользователей
    ca/cadatabase.cpp                           # база данных центра сертификации
    src/user.cpp                                # модель пользователя
    src/totpservice.cpp                         # сервис TOTP (Time-based One-Time Password)
    src/qrcodegen.cpp                           # генерация QR-кодов
    src/faceauthservice.cpp                     # сервис аутентификации по лицу
    src/faceauthwidget.cpp                      # виджет аутентификации по лицу
    src/camerathread.cpp                        # поток обработки камеры
    src/totpinputwidget.cpp                     # виджет ввода TOTP кода
    src/cameracapturewidget.cpp                 # виджет захвата камеры
    src/registrationtimerthread.cpp             # поток таймера регистрации
    src/videocapturethread.cpp                  # поток захвата видео
    src/kuznechikencryption.cpp                 # шифрование Kuznechik
    src/kuznechikwidget.cpp                     # виджет для работы с Kuznechik
    src/cryptofacade.cpp                        # фасад криптографических операций
    src/adminfileswidget.cpp                    # виджет управления пользователями
    src/sessionwidget.cpp                       # виджет управления сессиями
    src/forgotpasswordwidget.cpp                # виджет восстановления пароля
    src/emailservice.cpp                        # сервис отправки email
    ca/certificateworker.cpp                    # воркер для работы с сертификатами
    src/lockoutcleanupworker.cpp                # воркер очистки блокировок
    src/rbacguard.cpp                           # защита на основе ролей (RBAC)
    src/sessionmanager.cpp                      # менеджер сессий
    src/httpmiddleware.cpp                      # HTTP middleware
    ${STRIBOG_SOURCES}                          # исходные файлы Stribog
    ${KUZNECHIK_SOURCES}                        # исходные файлы Kuznechik
    ${RSA_SOURCES}                              # исходные файлы RSA-32768 (NTL-based)
    ${WIDGETS_SOURCES}                          # исходные файлы виджетов
)

# ============================================================================
# ЗАГОЛОВОЧНЫЕ ФАЙЛЫ ПРОЕКТА
# ============================================================================
# Список всех заголовочных файлов проекта
# ============================================================================

set(HEADERS
    src/apptheme.h
    src/appmessage.h
    src/qrcodegen.hpp                           # генерация QR-кодов
    src/mainwindow.h                            # главное окно приложения
    src/loginmemory.h
    src/facescanview.h
    src/authservice.h                           # сервис аутентификации
    src/database.h                              # работа с базой данных пользователей
    ca/cadatabase.h                             # база данных центра сертификации
    src/user.h                                  # модель пользователя
    src/totpservice.h                           # сервис TOTP
    src/faceauthservice.h                       # сервис аутентификации по лицу
    src/faceauthwidget.h                        # виджет аутентификации по лицу
    src/camerathread.h                          # поток обработки камеры
    src/totpinputwidget.h                       # виджет ввода TOTP кода
    src/cameracapturewidget.h                   # виджет захвата камеры
    src/registrationtimerthread.h               # поток таймера регистрации
    src/videocapturethread.h                    # поток захвата видео
    src/kuznechikencryption.h                   # шифрование Kuznechik
    src/kuznechikwidget.h                       # виджет для работы с Kuznechik
    src/cryptofacade.h                          # фасад криптографических операций
    src/adminfileswidget.h                      # виджет управления пользователями
    src/sessionwidget.h                         # виджет управления сессиями
    src/forgotpasswordwidget.h                  # виджет восстановления пароля
    src/emailservice.h                          # сервис отправки email
    ca/certificateworker.h                      # воркер для работы с сертификатами
    src/lockoutcleanupworker.h                  # воркер очистки блокировок
    src/rbacguard.h                             # защита на основе ролей (RBAC)
    src/sessionmanager.h                        # менеджер сессий
    src/httpmiddleware.h                        # HTTP middleware
    src/requestcontext.h                        # контекст HTTP запросов
)

# ============================================================================
# СОЗДАНИЕ ИСПОЛНЯЕМОГО ФАЙЛА 3FA
# ============================================================================
# Создаем основное приложение 3FA из всех исходных и заголовочных файлов
# ============================================================================

# Добавляем иконку приложения для Windows
if(WIN32)
    set(APP_ICON_RC "${CMAKE_SOURCE_DIR}/icons/app_icon.rc")
    add_executable(3FA ${SOURCES} ${HEADERS} ${APP_ICON_RC})
    set_property(SOURCE algorithms/RSA-32768/RSACrypto.cpp APPEND PROPERTY COMPILE_DEFINITIONS OPENSSL_FOUND)
else()
    add_executable(3FA ${SOURCES} ${HEADERS})
endif()
target_include_directories(3FA PRIVATE "${NTL_INCLUDE_DIR}")
qt_add_resources(3FA "material_symbols"
    PREFIX "/3fa"
    BASE "${CMAKE_CURRENT_SOURCE_DIR}/src/assets"
    FILES src/assets/material-symbols/MaterialSymbolsRounded.ttf src/assets/material-symbols/LICENSE
)

# ============================================================================
# ПОДКЛЮЧЕНИЕ БИБЛИОТЕК К ПРИЛОЖЕНИЮ 3FA
# ============================================================================
# Связываем приложение с необходимыми библиотеками:
# - Qt6: GUI, сеть, базы данных, многопоточность
# - OpenCV: обработка изображений и видео
# - OpenSSL: криптография
# - pthread: поддержка многопоточности
# ============================================================================

target_link_libraries(3FA PRIVATE
    Qt6::Core                                   # базовые классы Qt
    Qt6::Widgets                                # виджеты Qt
    Qt6::Sql                                    # работа с базами данных
    Qt6::Network                                # сетевые операции
    Qt6::PrintSupport                           # поддержка печати
    Qt6::Concurrent                             # параллельные вычисления
    ${OpenCV_LIBS}                              # библиотеки OpenCV
    OpenSSL::Crypto                             # криптографические функции OpenSSL
    pthread                                     # поддержка POSIX потоков
    "${NTL_LIBRARY}"                            # NTL библиотека для RSA
)

# Исправление ошибки линковки Qt6EntryPoint на Windows с MinGW
if(WIN32)
    # Проблема: Qt6EntryPoint требует __imp___argc и __imp___argv, которых нет в MinGW
    # Решение: отключаем WIN32_EXECUTABLE (выше) и используем стандартный main()
    # Это позволяет приложению работать как консольное, но GUI все равно будет работать
    # Добавляем флаги линковки для правильной работы на Windows
    set_target_properties(3FA PROPERTIES
        LINK_FLAGS "-Wl,--enable-auto-import"
    )
    target_link_libraries(3FA PRIVATE iphlpapi crypt32)
endif()

# RSA-32768 теперь использует NTL - Metal GPU ускорение не требуется

# ============================================================================
# ФЛАГИ КОМПИЛЯТОРА ДЛЯ ОПТИМИЗАЦИИ
# ============================================================================
# Устанавливаем флаги компилятора для оптимизации производительности
# ============================================================================

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(3FA PRIVATE 
        -pthread 
        -O3 
        -Wno-stringop-overflow                                    # отключаем предупреждения о переполнении буфера (ложные срабатывания с std::vector<bool>)
    )           # поддержка потоков и оптимизация уровня 3
    
endif()

# ============================================================================
# СОЗДАНИЕ ИСПОЛНЯЕМОГО ФАЙЛА MINICA (МИНИМАЛЬНЫЙ CA CLI)
# ============================================================================
# Создаем консольное приложение для управления центром сертификации
# без графического интерфейса
# ============================================================================

add_executable(minica ca/minica.cpp ca/cadatabase.cpp src/rbacguard.cpp src/sessionmanager.cpp src/httpmiddleware.cpp)
target_link_libraries(minica Qt6::Core Qt6::Sql OpenSSL::Crypto OpenSSL::SSL)
if(WIN32)
    target_link_libraries(minica ws2_32)
endif()

# ДЕЙСТВИЕ 1: ПОДДЕРЖКА SQLITE3
find_library(SQLITE3_LIB sqlite3)
if (SQLITE3_LIB)
    target_link_libraries(minica ${SQLITE3_LIB})
    target_compile_definitions(minica PRIVATE WITH_SQLITE3=1)
endif()

# ДЕЙСТВИЕ 2: ОПЦИОНАЛЬНАЯ ПОДДЕРЖКА OPENSSL ENGINE (ENGINE_PKCS11)
include(CheckIncludeFile)
check_include_file("openssl/engine.h" HAVE_OPENSSL_ENGINE_H)
if (HAVE_OPENSSL_ENGINE_H)
    target_compile_definitions(minica PRIVATE WITH_ENGINE_PKCS11=1)
endif()

# ============================================================================
# КОПИРОВАНИЕ РЕСУРСОВ В БУНДЛ ПРИЛОЖЕНИЯ
# ============================================================================
# Копируем необходимые ресурсы (распознавание лиц, иконки) в бундл приложения
# ============================================================================

# ДЕЙСТВИЕ 1: КОПИРОВАНИЕ QT DLL ДЛЯ WINDOWS
# Автоматическое копирование всех необходимых Qt DLL в директорию с исполняемым файлом
if(WIN32)
    find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS ${Qt6_DIR}/../../../bin ${Qt6_DIR}/../../bin)
    if(WINDEPLOYQT_EXECUTABLE)
        add_custom_command(TARGET 3FA POST_BUILD
            COMMAND ${WINDEPLOYQT_EXECUTABLE} $<TARGET_FILE:3FA>
            COMMENT "Deploying Qt libraries"
        )
    else()
        message(WARNING "windeployqt not found. Qt DLL may not be copied automatically.")
    endif()
endif()

# ДЕЙСТВИЕ 2: КОПИРОВАНИЕ РЕСУРСОВ РАСПОЗНАВАНИЯ ЛИЦ
# Копируем ресурсы для распознавания лиц в бундл, если директория существует
set(FACE_RESOURCE_DIR "${CMAKE_SOURCE_DIR}/resources/face")         # путь к ресурсам распознавания лиц
if(EXISTS "${FACE_RESOURCE_DIR}")
    add_custom_command(TARGET 3FA POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:3FA>/resources/face"  # создание директории
        COMMAND ${CMAKE_COMMAND} -E copy_directory "${FACE_RESOURCE_DIR}" "$<TARGET_FILE_DIR:3FA>/resources/face"  # копирование ресурсов
        COMMENT "Copying face recognition resources")               # комментарий для сборки
endif()

# ДЕЙСТВИЕ 3: КОПИРОВАНИЕ ИКОНКИ ПРИЛОЖЕНИЯ
# Копируем иконку приложения в бундл для macOS
set(APP_ICON_PATH "${CMAKE_SOURCE_DIR}/icons/app_icon.icns")        # путь к иконке приложения
if(APPLE AND EXISTS "${APP_ICON_PATH}")
    add_custom_command(TARGET 3FA POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:3FA>/../Resources"                         # создание директории Resources
        COMMAND ${CMAKE_COMMAND} -E copy "${APP_ICON_PATH}" "$<TARGET_FILE_DIR:3FA>/../Resources/app_icon.icns"  # копирование иконки
        COMMENT "Copying app icon")                                 # комментарий для сборки
endif()

# ============================================================================
# УСТАНОВКА СВОЙСТВ ЦЕЛЕВОГО ФАЙЛА
# ============================================================================
# Настраиваем свойства исполняемого файла для разных платформ
# ============================================================================

set_target_properties(3FA PROPERTIES
    # WIN32_EXECUTABLE TRUE                                         # Windows: GUI приложение (временно отключено из-за Qt6EntryPoint)
    MACOSX_BUNDLE TRUE                                              # macOS: бундл приложения
    MACOSX_BUNDLE_ICON_FILE app_icon.icns                           # macOS: файл иконки
)

# ============================================================================
# СОЗДАНИЕ ПОЛЬЗОВАТЕЛЬСКОЙ ЦЕЛИ ДЛЯ ЗАПУСКА ПРИЛОЖЕНИЯ
# ============================================================================
# Добавляем цель "run" для удобного запуска приложения после сборки
# ============================================================================

add_custom_target(run
    COMMAND $<TARGET_FILE:3FA>
    WORKING_DIRECTORY $<TARGET_FILE_DIR:3FA>
    DEPENDS 3FA minica
    COMMENT "Running 3FA application")
