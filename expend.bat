@echo off
chcp 65001 >nul
setlocal EnableExtensions

title Auto Expand Repository - gufau9089-tech/C

echo ==========================================
echo   Автоматическое расширение репозитория
echo ==========================================
echo.

REM ==========================================
REM НАСТРОЙКИ
REM ==========================================

set "REPO_URL=https://github.com/gufau9089-tech/C.git"

set "CJSON_URL=https://github.com/DaveGamble/cJSON.git"
set "STB_URL=https://github.com/nothings/stb.git"

REM Версия SQLite:
REM 3.53.4 = 3530400
set "SQLITE_VERSION=3530400"
set "SQLITE_ZIP=sqlite-amalgamation-%SQLITE_VERSION%.zip"
set "SQLITE_URL=https://www.sqlite.org/2026/%SQLITE_ZIP%"

echo Репозиторий:
echo %REPO_URL%
echo.

REM ==========================================
REM 1. ПРОВЕРКА GIT
REM ==========================================

echo [1/7] Проверка Git...
echo.

git --version >nul 2>&1

if errorlevel 1 (
    echo ==========================================
    echo ОШИБКА: Git не найден!
    echo ==========================================
    echo.
    echo Установите Git и запустите скрипт снова.
    echo.
    pause
    exit /b 1
)

git --version
echo Git найден.
echo.

REM ==========================================
REM 2. НАСТРОЙКА GIT
REM ==========================================

echo [2/7] Настройка Git-репозитория...
echo.

REM Настройки автора Git
git config --global user.name "gufau9089-tech"
git config --global user.email "gufau9089@gmail.com"

if not exist ".git" (
    echo Локальный Git-репозиторий не найден.
    echo Создание нового репозитория...

    git init

    if errorlevel 1 (
        echo ОШИБКА: git init завершился с ошибкой.
        pause
        exit /b 1
    )
)

REM Удаляем старый origin, если существует
git remote remove origin >nul 2>&1

REM Добавляем правильный origin
git remote add origin "%REPO_URL%"

if errorlevel 1 (
    echo ОШИБКА: Не удалось добавить origin.
    pause
    exit /b 1
)

echo Remote:
git remote -v
echo.

REM ==========================================
REM 3. CJSON
REM ==========================================

echo [3/7] Загрузка cJSON...
echo.

if exist "cjson_temp" (
    echo Удаление старого cjson_temp...
    rmdir /s /q "cjson_temp"
)

git clone --depth 1 "%CJSON_URL%" "cjson_temp"

if errorlevel 1 (
    echo.
    echo ==========================================
    echo ОШИБКА: Не удалось скачать cJSON.
    echo ==========================================
    echo.
    pause
    exit /b 1
)

if not exist "cJSON" (
    mkdir "cJSON"
)

if exist "cjson_temp\cJSON.c" (
    copy /Y "cjson_temp\cJSON.c" "cJSON\cJSON.c" >nul
) else (
    echo ОШИБКА: cJSON.c не найден!
    rmdir /s /q "cjson_temp"
    pause
    exit /b 1
)

if exist "cjson_temp\cJSON.h" (
    copy /Y "cjson_temp\cJSON.h" "cJSON\cJSON.h" >nul
) else (
    echo ОШИБКА: cJSON.h не найден!
    rmdir /s /q "cjson_temp"
    pause
    exit /b 1
)

rmdir /s /q "cjson_temp"

echo cJSON готов.
echo.

REM ==========================================
REM 4. STB_IMAGE
REM ==========================================

echo [4/7] Загрузка stb_image...
echo.

if exist "stb_temp" (
    echo Удаление старого stb_temp...
    rmdir /s /q "stb_temp"
)

git clone --depth 1 "%STB_URL%" "stb_temp"

if errorlevel 1 (
    echo.
    echo ==========================================
    echo ОШИБКА: Не удалось скачать stb.
    echo ==========================================
    echo.
    pause
    exit /b 1
)

if not exist "stb" (
    mkdir "stb"
)

if exist "stb_temp\stb_image.h" (
    copy /Y "stb_temp\stb_image.h" "stb\stb_image.h" >nul
) else (
    echo ОШИБКА: stb_image.h не найден!
    rmdir /s /q "stb_temp"
    pause
    exit /b 1
)

rmdir /s /q "stb_temp"

echo stb_image готов.
echo.

REM ==========================================
REM 5. SQLITE
REM ==========================================

echo [5/7] Загрузка SQLite...
echo.

if exist "sqlite_temp" (
    echo Удаление старого sqlite_temp...
    rmdir /s /q "sqlite_temp"
)

if not exist "sqlite3" (
    mkdir "sqlite3"
)

echo URL SQLite:
echo %SQLITE_URL%
echo.

echo Скачивание SQLite...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '%SQLITE_URL%' -OutFile '%SQLITE_ZIP%'"

if errorlevel 1 (
    echo.
    echo ==========================================
    echo ОШИБКА: Не удалось скачать SQLite!
    echo ==========================================
    echo.
    echo URL:
    echo %SQLITE_URL%
    echo.
    pause
    exit /b 1
)

if not exist "%SQLITE_ZIP%" (
    echo ОШИБКА: ZIP-файл SQLite не создан.
    pause
    exit /b 1
)

echo Распаковка SQLite...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Expand-Archive -Path '%SQLITE_ZIP%' -DestinationPath 'sqlite_temp' -Force"

if errorlevel 1 (
    echo.
    echo ==========================================
    echo ОШИБКА: Не удалось распаковать SQLite!
    echo ==========================================
    echo.
    pause
    exit /b 1
)

set "SQLITE_FOLDER=sqlite_temp\sqlite-amalgamation-%SQLITE_VERSION%"

if not exist "%SQLITE_FOLDER%\sqlite3.c" (
    echo ОШИБКА: sqlite3.c не найден.
    echo Ожидался:
    echo %SQLITE_FOLDER%\sqlite3.c
    pause
    exit /b 1
)

if not exist "%SQLITE_FOLDER%\sqlite3.h" (
    echo ОШИБКА: sqlite3.h не найден.
    echo Ожидался:
    echo %SQLITE_FOLDER%\sqlite3.h
    pause
    exit /b 1
)

copy /Y "%SQLITE_FOLDER%\sqlite3.c" "sqlite3\sqlite3.c" >nul
copy /Y "%SQLITE_FOLDER%\sqlite3.h" "sqlite3\sqlite3.h" >nul

rmdir /s /q "sqlite_temp"
del /q "%SQLITE_ZIP%" >nul 2>&1

echo SQLite готов.
echo.

REM ==========================================
REM 6. CMAKE
REM ==========================================

echo [6/7] Создание CMakeLists.txt...
echo.

REM ------------------------------------------
REM cJSON CMake
REM ------------------------------------------

if not exist "cJSON\CMakeLists.txt" (
    (
        echo cmake_minimum_required^(VERSION 3.15^)
        echo project^(cJSON C^)
        echo.
        echo add_library^(cjson STATIC cJSON.c^)
        echo.
        echo target_include_directories^(cjson PUBLIC
        echo     ${CMAKE_CURRENT_SOURCE_DIR}
        echo ^)
    ) > "cJSON\CMakeLists.txt"
)

REM ------------------------------------------
REM stb CMake
REM ------------------------------------------

if not exist "stb\CMakeLists.txt" (
    (
        echo cmake_minimum_required^(VERSION 3.15^)
        echo project^(stb C^)
        echo.
        echo add_library^(stb INTERFACE^)
        echo.
        echo target_include_directories^(stb INTERFACE
        echo     ${CMAKE_CURRENT_SOURCE_DIR}
        echo ^)
    ) > "stb\CMakeLists.txt"
)

REM ------------------------------------------
REM SQLite CMake
REM ------------------------------------------

if not exist "sqlite3\CMakeLists.txt" (
    (
        echo cmake_minimum_required^(VERSION 3.15^)
        echo project^(sqlite3 C^)
        echo.
        echo add_library^(sqlite3 STATIC sqlite3.c^)
        echo.
        echo target_include_directories^(sqlite3 PUBLIC
        echo     ${CMAKE_CURRENT_SOURCE_DIR}
        echo ^)
    ) > "sqlite3\CMakeLists.txt"
)

echo CMakeLists.txt готовы.
echo.

REM ==========================================
REM 7. GIT COMMIT / PULL / PUSH
REM ==========================================

echo [7/7] Синхронизация с GitHub...
echo.

REM ------------------------------------------
REM Устанавливаем main
REM ------------------------------------------

git branch -M main

if errorlevel 1 (
    echo ОШИБКА: Не удалось установить ветку main.
    pause
    exit /b 1
)

REM ------------------------------------------
REM Получаем удалённую историю
REM ------------------------------------------

echo Получение данных из GitHub...
echo.

git fetch origin main

if errorlevel 1 (
    echo.
    echo ==========================================
    echo ОШИБКА: git fetch завершился с ошибкой.
    echo ==========================================
    echo.
    echo Проверьте:
    echo - интернет-соединение;
    echo - доступ к GitHub;
    echo - авторизацию GitHub.
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------
REM Проверяем, есть ли удалённая ветка
REM ------------------------------------------

git show-ref --verify --quiet refs/remotes/origin/main

if errorlevel 1 (
    echo.
    echo Удалённой ветки main пока нет.
    echo Создаём первый push...
    echo.

    git add .

    git diff --cached --quiet

    if errorlevel 1 (
        git commit -m "Add cJSON, stb_image and SQLite libraries"

        if errorlevel 1 (
            echo ОШИБКА: Не удалось создать commit.
            pause
            exit /b 1
        )
    )

    git push -u origin main

    if errorlevel 1 (
        echo.
        echo ==========================================
        echo ОШИБКА: git push завершился с ошибкой.
        echo ==========================================
        echo.
        pause
        exit /b 1
    )

    goto SUCCESS
)

REM ------------------------------------------
REM Сохраняем локальные изменения
REM ------------------------------------------

echo Добавление локальных файлов...

git add .

git diff --cached --quiet

if errorlevel 1 (
    echo Создание локального commit...

    git commit -m "Add cJSON, stb_image and SQLite libraries"

    if errorlevel 1 (
        echo.
        echo ==========================================
        echo ОШИБКА: Не удалось создать commit.
        echo ==========================================
        echo.
        pause
        exit /b 1
    )
) else (
    echo Новых изменений для commit нет.
)

echo.

REM ------------------------------------------
REM Объединяем истории
REM ------------------------------------------

echo Объединение локальной истории с GitHub...
echo.

git pull origin main --allow-unrelated-histories --no-edit

if errorlevel 1 (
    echo.
    echo ==========================================
    echo ОШИБКА: Возник конфликт при объединении!
    echo ==========================================
    echo.
    echo Выполните:
    echo.
    echo     git status
    echo.
    echo После исправления конфликтов:
    echo.
    echo     git add .
    echo     git commit
    echo     git push -u origin main
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------
REM Повторно добавляем изменения после merge
REM ------------------------------------------

git add .

git diff --cached --quiet

if errorlevel 1 (
    git commit -m "Merge remote repository and add libraries"
)

REM ------------------------------------------
REM Push
REM ------------------------------------------

echo.
echo Отправка изменений в GitHub...
echo.

git push -u origin main

if errorlevel 1 (
    echo.
    echo ==========================================
    echo ОШИБКА: git push завершился с ошибкой.
    echo ==========================================
    echo.
    echo Проверьте:
    echo - авторизацию GitHub;
    echo - права доступа к репозиторию;
    echo - состояние ветки main.
    echo.
    pause
    exit /b 1
)

REM ==========================================
REM УСПЕХ
REM ==========================================

:SUCCESS

echo.
echo ==========================================
echo       ВСЁ УСПЕШНО ЗАВЕРШЕНО!
echo ==========================================
echo.
echo Репозиторий:
echo %REPO_URL%
echo.
echo Добавленные библиотеки:
echo.
echo   cJSON
echo       cJSON\cJSON.c
echo       cJSON\cJSON.h
echo       cJSON\CMakeLists.txt
echo.
echo   stb_image
echo       stb\stb_image.h
echo       stb\CMakeLists.txt
echo.
echo   SQLite
echo       sqlite3\sqlite3.c
echo       sqlite3\sqlite3.h
echo       sqlite3\CMakeLists.txt
echo.
echo Изменения отправлены в GitHub.
echo ==========================================
echo.

pause
endlocal
