#!/bin/bash

# ==============================================================================
# Скрипт: security_check.sh
# Призначення: Автоматизований базовий security-аудит Linux-сервера перед
#              розгортанням production-проєкту.
# Використання: ./security_check.sh [--quick | --full]
# ==============================================================================

# --- Кольори для виводу в консоль (ANSI) ---
BLUE='\e[34m'
GREEN='\e[32m'
YELLOW='\e[33m'
RED='\e[31m'
BOLD='\e[1m'
NC='\e[0m' # Скидання кольору

# --- Обробка аргументів командного рядка (--quick / --full) ---
MODE="full" # За замовчуванням виконуємо повну перевірку

if [ "$1" == "--quick" ]; then
    MODE="quick"
elif [ "$1" == "--full" ] || [ -z "$1" ]; then
    MODE="full"
else
    echo -e "${RED}[ПОМИЛКА] Невідомий аргумент: $1${NC}"
    echo "Використання: $0 [--quick | --full]"
    exit 1
fi

# --- Налаштування файлу звіту ---
REPORT_FILE="security_report_$(date +%Y%m%d_%H%M%S).txt"

# --- Змінні для підрахунку ризиків та статусів у підсумковому блоці [7] ---
ALERTS_COUNT=0
STATUS_SEC1="OK"
STATUS_SEC2="OK"
STATUS_SEC3="OK"
STATUS_SEC4="OK"
STATUS_SEC5="OK"
STATUS_SEC6="OK"

# Основна функція перевірки
run_audit() {
    echo "======================================================================"
    echo " ЗВІТ З БЕЗПЕКИ СЕРЕДОВИЩА (SECURITY AUDIT REPORT)"
    echo " Дата запуску: $(date '+%Y-%m-%d %H:%M:%S')"
    echo " Режим перевірки: ${MODE^^}"
    if [ "$EUID" -eq 0 ]; then
        echo " Рівень привілеїв: ROOT (повний доступ)"
    else
        echo -e " Рівень привілеїв: ${YELLOW}Звичайний користувач (частина перевірок буде пропущена без sudo)${NC}"
    fi
    echo "======================================================================"

    # ==========================================================================
    # [1] ЗАГАЛЬНА ІНФОРМАЦІЯ ПРО СИСТЕМУ
    # ==========================================================================
    echo ""
    echo "=== [1] Інформація про систему ==="
    echo ""
    echo -e "${BLUE}Версія ядра:${NC} $(uname -r); ${BLUE}Архітектура:${NC} $(uname -m)"
    echo -e "${BLUE}Повний вивід uname -a:${NC} $(uname -a)"
    echo -e "${BLUE}Назва хоста:${NC} $(hostname)"
    echo -e "${BLUE}Аптайм хоста:${NC} $(uptime -p 2>/dev/null || uptime)"
    if [ -r /etc/os-release ]; then
        OS_NAME=$(grep 'PRETTY_NAME' /etc/os-release | cut -d '"' -f 2)
        echo -e "${BLUE}Дистрибутив хоста:${NC} $OS_NAME"
    else
        echo -e "${BLUE}Дистрибутив хоста:${NC} Не вдалося визначити (/etc/os-release недоступний)"
        STATUS_SEC1="WARNING"
    fi
    echo "========================================="

    # ==========================================================================
    # [2] КОРИСТУВАЧІ ТА АВТЕНТИФІКАЦІЯ
    # ==========================================================================
    echo ""
    echo "=== [2] Користувачі та автентифікація ==="
    echo ""
    echo -e "${BLUE}Поточний користувач та його права (групи):${NC} $(id)"

    echo -e "${BLUE}Список дозволених sudo-команд:${NC}"
    if sudo -n -l 2>/dev/null; then
        echo "  -> Доступні sudo-привілеї виведено вище."
    else
        echo -e "  -> ${YELLOW}[УВАГА] Немає прав sudo або потрібен пароль (запустіть через sudo).${NC}"
    fi

    echo -e "${BLUE}Список користувачів з UID = 0 (права root):${NC}"
    ROOT_USERS=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    ROOT_COUNT=$(echo "$ROOT_USERS" | wc -w)
    echo "  Знайдено користувачів ($ROOT_COUNT): $(echo "$ROOT_USERS" | tr '\n' ' ')"
    if [ "$ROOT_COUNT" -gt 1 ]; then
        echo -e "  -> ${RED}[CRITICAL] Виявлено додаткових користувачів із правами root!${NC}"
        STATUS_SEC2="CRITICAL"
        ALERTS_COUNT=$((ALERTS_COUNT + 1))
    fi

    echo -e "${BLUE}Останні 10 успішних входів:${NC}"
    if command -v last >/dev/null 2>&1; then
        last -F -n 10
    else
        echo "  Утиліту last не знайдено в системі."
    fi

    echo -e "${BLUE}Останні 10 невдалих спроб входу:${NC}"
    if command -v lastb >/dev/null 2>&1; then
        if [ -r /var/log/btmp ]; then
            FAILED_LOGINS=$(lastb -n 10)
            echo "$FAILED_LOGINS"
            if echo "$FAILED_LOGINS" | grep -qvE "^$|^btmp begins"; then
                echo -e "  -> ${YELLOW}[WARNING] Зафіксовано невдалі спроби входу в систему.${NC}"
                [ "$STATUS_SEC2" == "OK" ] && STATUS_SEC2="WARNING"
                ALERTS_COUNT=$((ALERTS_COUNT + 1))
            fi
        else
            echo -e "  -> ${YELLOW}[УВАГА] Немає доступу до /var/log/btmp (потрібні права sudo).${NC}"
        fi
    else
        echo "  Утиліту lastb не знайдено в системі."
    fi
    echo "========================================="

    # ==========================================================================
    # [3] ПРАВА ДОСТУПУ ДО ФАЙЛІВ
    # ==========================================================================
    echo ""
    echo "=== [3] Права доступу до файлів ==="
    echo ""
    SUID_FILES=$(find / -perm -4000 -type f 2>/dev/null)
    SUID_COUNT=$(echo "$SUID_FILES" | grep -c '^/')
    echo -e "${BLUE}Знайдено SUID-файлів: $SUID_COUNT${NC}"
    echo "$SUID_FILES"
    if [ "$SUID_COUNT" -gt 35 ]; then
        echo -e "  -> ${YELLOW}[WARNING] Кількість SUID-файлів перевищує базовий поріг (35). Перевірте список!${NC}"
        STATUS_SEC3="WARNING"
        ALERTS_COUNT=$((ALERTS_COUNT + 1))
    fi

    SGID_FILES=$(find / -perm -2000 -type f 2>/dev/null)
    SGID_COUNT=$(echo "$SGID_FILES" | grep -c '^/')
    echo -e "${BLUE}Знайдено SGID-файлів: $SGID_COUNT${NC}"
    echo "$SGID_FILES"

    WW_FILES=$(find / -path /proc -prune -o -path /sys -prune -o -perm -o+w -type f -print 2>/dev/null)
    WW_COUNT=$(echo "$WW_FILES" | grep -c '^/')
    echo -e "${BLUE}Знайдено world-writable файлів (окрім /proc та /sys): $WW_COUNT${NC}"
    if [ "$WW_COUNT" -gt 0 ]; then
        echo -e "  -> ${RED}[CRITICAL] Виявлено файли, відкриті на запис для всіх користувачів! Перші 15:${NC}"
        echo "$WW_FILES" | head -n 15
        STATUS_SEC3="CRITICAL"
        ALERTS_COUNT=$((ALERTS_COUNT + 1))
    fi

    if [ "$MODE" == "full" ]; then
        echo -e "${BLUE}[FULL] Перевірка привілеїв файлів (getcap):${NC}"
        if command -v getcap >/dev/null 2>&1; then
            getcap -r / 2>/dev/null
        else
            echo "  Утиліту getcap не знайдено в системі."
        fi
    else
        echo -e "${BLUE}[QUICK] Перевірку getcap пропущено у швидкому режимі.${NC}"
    fi
    echo "========================================="

    # ==========================================================================
    # [4] МЕРЕЖА
    # ==========================================================================
    echo ""
    echo "=== [4] Мережа ==="
    echo ""
    if command -v ss >/dev/null 2>&1; then
        echo -e "${BLUE}Активні слухаючі порти (ss):${NC}"
        LISTEN_PORTS=$(ss -tulnp 2>/dev/null)
        echo "$LISTEN_PORTS"

        echo -e "${BLUE}Активні мережеві з'єднання (ss):${NC}"
        ss -tunp state established 2>/dev/null
    elif command -v netstat >/dev/null 2>&1; then
        echo -e "${BLUE}Активні слухаючі порти (netstat):${NC}"
        LISTEN_PORTS=$(netstat -tulnp 2>/dev/null)
        echo "$LISTEN_PORTS"

        echo -e "${BLUE}Активні мережеві з'єднання (netstat):${NC}"
        netstat -tunp 2>/dev/null | grep ESTABLISHED
    else
        echo "  Утиліти ss та netstat не знайдено в системі."
        STATUS_SEC4="WARNING"
    fi

    EXPOSED_PORTS=$(echo "$LISTEN_PORTS" | grep -E "0\.0\.0\.0:|\[::\]:" | grep -v ":22 ")
    if [ -n "$EXPOSED_PORTS" ]; then
        echo -e "  -> ${YELLOW}[WARNING] Виявлено порти (окрім SSH 22), відкриті на всі мережеві інтерфейси!${NC}"
        STATUS_SEC4="WARNING"
        ALERTS_COUNT=$((ALERTS_COUNT + 1))
    fi
    echo "========================================="

    # ==========================================================================
    # [5] ПРОЦЕСИ ТА АВТОЗАПУСК
    # ==========================================================================
    echo ""
    echo "=== [5] Процеси та автозапуск ==="
    echo ""
    echo -e "${BLUE}Дерево процесів:${NC}"
    PS_TREE=$(ps aux --forest)
    PS_TREE_COUNT=$(($(echo "$PS_TREE" | wc -l) - 1))
    echo "  Загальна кількість процесів: $PS_TREE_COUNT. Виводимо перші 30:"
    echo "$PS_TREE" | head -n 31

    echo -e "${BLUE}Заплановані задачі (crontab поточного користувача):${NC}"
    if crontab -l >/dev/null 2>&1; then
        crontab -l
        echo -e "  -> ${YELLOW}[WARNING] Знайдено активний crontab поточного користувача. Перевірте завдання.${NC}"
        STATUS_SEC5="WARNING"
        ALERTS_COUNT=$((ALERTS_COUNT + 1))
    else
        echo "  Запланованих задач для поточного користувача немає."
    fi

    echo -e "${BLUE}Системні заплановані задачі (/etc/cron.*):${NC}"
    ls -la /etc/cron.* 2>/dev/null

    if [ "$MODE" == "full" ]; then
        echo -e "${BLUE}[FULL] Активні systemd-сервіси, що автозапускаються:${NC}"
        if command -v systemctl >/dev/null 2>&1; then
            systemctl list-unit-files --type=service --state=enabled --no-pager
        else
            echo "  Утиліту systemctl не знайдено (можливо, це Docker-контейнер)."
        fi
    else
        echo -e "${BLUE}[QUICK] Перевірку systemd-сервісів пропущено у швидкому режимі.${NC}"
    fi
    echo "========================================="

    # ==========================================================================
    # [6] ЦІЛІСНІСТЬ ТА СВІЖІ ЗМІНИ
    # ==========================================================================
    echo ""
    echo "=== [6] Цілісність та свіжі зміни ==="
    echo ""
    echo -e "${BLUE}Файли, змінені за останні 24 години у ключових директоріях:${NC}"
    for DIR in /etc /bin /usr/bin; do
        echo "  Директорія $DIR:"
        MOD_FILES=$(find "$DIR" -type f -mtime -1 2>/dev/null)
        if [ -z "$MOD_FILES" ]; then
            echo "    Змінених файлів за останні 24 години не виявлено."
        else
            echo "$MOD_FILES" | sed 's/^/    /'
            # Якщо змінено виконувані файли в /bin або /usr/bin — це критичний індикатор
            if [ "$DIR" == "/bin" ] || [ "$DIR" == "/usr/bin" ]; then
                echo -e "    -> ${RED}[CRITICAL] Увага! Змінено системні бінарні файли за останні 24 години!${NC}"
                STATUS_SEC6="CRITICAL"
                ALERTS_COUNT=$((ALERTS_COUNT + 1))
            else
                # ОСЬ ТУТ: додаємо збільшення лічильника для змін у /etc
                [ "$STATUS_SEC6" == "OK" ] && STATUS_SEC6="WARNING"
                ALERTS_COUNT=$((ALERTS_COUNT + 1))
            fi
        fi
    done

    if [ "$MODE" == "full" ]; then
        echo -e "${BLUE}[FULL] Перевірка встановлених пакетів на модифікацію:${NC}"
        if [ "$EUID" -ne 0 ]; then
            echo -e "  -> ${YELLOW}[УВАГА] Для перевірки цілісності пакетів потрібні права sudo. Пропускаємо.${NC}"
        elif command -v dpkg >/dev/null 2>&1; then
            if command -v debsums >/dev/null 2>&1; then
                PKG_MODS=$(timeout 30s debsums -ce 2>/dev/null)
                if [ -z "$PKG_MODS" ]; then
                    echo "  Модифікованих конфігураційних файлів пакетів не виявлено (debsums)."
                else
                    echo -e "  -> ${YELLOW}[WARNING] Виявлено змінені конфігураційні файли:${NC}"
                    echo "$PKG_MODS"
                    [ "$STATUS_SEC6" == "OK" ] && STATUS_SEC6="WARNING"
                    ALERTS_COUNT=$((ALERTS_COUNT + 1))
                fi
            else
                echo "  Утиліту debsums не встановлено в системі (Debian/Ubuntu/Kali)."
            fi
        elif command -v rpm >/dev/null 2>&1; then
            PKG_MODS=$(timeout 30s rpm -Va 2>/dev/null)
            if [ -z "$PKG_MODS" ]; then
                echo "  Модифікованих пакетів не виявлено (rpm)."
            else
                echo -e "  -> ${YELLOW}[WARNING] Виявлено відхилення у файлах пакетів (rpm):${NC}"
                echo "$PKG_MODS" | head -n 20
                [ "$STATUS_SEC6" == "OK" ] && STATUS_SEC6="WARNING"
                ALERTS_COUNT=$((ALERTS_COUNT + 1))
            fi
        else
            echo "  Менеджер пакетів dpkg або rpm не знайдено."
        fi
    else
        echo -e "${BLUE}[QUICK] Перевірку цілісності пакетів пропущено у швидкому режимі.${NC}"
    fi
    echo "========================================="

    # ==========================================================================
    # [7] ПІДСУМКОВИЙ ЗВІТ
    # ==========================================================================
    echo ""
    echo "=== [7] Підсумковий звіт ==="
    echo ""
    print_status() {
        local section_name="$1"
        local status="$2"
        if [ "$status" == "OK" ]; then
            echo -e "  ${GREEN}[OK]${NC}       $section_name"
        elif [ "$status" == "WARNING" ]; then
            echo -e "  ${YELLOW}[WARNING]${NC}  $section_name"
        else
            echo -e "  ${RED}[CRITICAL]${NC} $section_name"
        fi
    }

    print_status "[1] Інформація про систему" "$STATUS_SEC1"
    print_status "[2] Користувачі та автентифікація" "$STATUS_SEC2"
    print_status "[3] Права доступу до файлів" "$STATUS_SEC3"
    print_status "[4] Мережа" "$STATUS_SEC4"
    print_status "[5] Процеси та автозапуск" "$STATUS_SEC5"
    print_status "[6] Цілісність та свіжі зміни" "$STATUS_SEC6"
    echo ""
    echo -e "${BOLD}Загальна кількість потенційних ризиків / попереджень: $ALERTS_COUNT${NC}"
    if [ "$ALERTS_COUNT" -eq 0 ]; then
        echo -e "${GREEN}[OK] Критичних проблем не виявлено. Середовище готове до розгортання.${NC}"
    else
        echo -e "${YELLOW}[УВАГА] Рекомендується перевірити зазначені попередження перед деплоєм!${NC}"
    fi
    echo "======================================================================"
    echo "Звіт збережено у файл: $REPORT_FILE"
}

# ==============================================================================
# ЗАПУСК
# ==============================================================================
# Запускаємо функцію аудиту:
# - на екран (stdout) виводимо з кольорами
# - через tee + sed очищуємо ANSI-коди кольорів і зберігаємо чистий текст у файл
run_audit | tee >(sed -r 's/\x1B\[[0-9;]*[mK]//g' > "$REPORT_FILE")
