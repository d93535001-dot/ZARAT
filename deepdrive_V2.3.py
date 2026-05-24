"""
DeepDrive V2.3
---------------------------------------
Комплексный инструмент для форензики (криминалистики), восстановления данных,
низкоуровневой работы с накопителями и создания загрузочных носителей.
"""

import os
import sys
import csv
import time
import ctypes
import subprocess
import re
import json
import math
import struct
import threading
import hashlib
import logging
import tempfile
import traceback
import collections
import msvcrt
import urllib.request
import random
from datetime import datetime
from pathlib import Path
try:
    import yara
except ImportError:
    yara = None

# =====================================================================
# ВЕРСИЯ
# =====================================================================
APP_VERSION = "V2.3"


# =====================================================================
# СИСТЕМНЫЕ УТИЛИТЫ И БАЗОВЫЕ ФУНКЦИИ
# =====================================================================

def is_admin() -> bool:
    """Проверяет, запущена ли программа с правами Администратора."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def request_admin() -> bool:
    """Запрашивает повышение прав через UAC."""
    try:
        executable = sys.executable
        arguments = f'"{os.path.abspath(sys.argv[0])}"'
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, arguments, None, 1)
        return int(ret) > 32
    except Exception:
        return False


def fmt_size(bytes_size: float) -> str:
    """Форматирует байты в читаемый вид (КБ, МБ, ГБ)."""
    for unit in ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} ПБ"


# =====================================================================
# КЛАССЫ ИНФРАСТРУКТУРЫ И ЛОГИРОВАНИЯ
# =====================================================================

class ForensicLogger:
    """Система криминалистического логирования сессии."""
    def __init__(self):
        self.log_dir = Path(tempfile.gettempdir()) / "DeepDriveLogs"
        self.log_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = self.log_dir / f"session_{timestamp}.log"

        self._cleanup_old_logs()

        logging.basicConfig(
            filename=str(self.log_file),
            level=logging.INFO,
            format='%(asctime)s - [%(levelname)s] - %(message)s',
            encoding='utf-8'
        )
        self.info(f"=== DEEPDRIVE {APP_VERSION} СЕССИЯ НАЧАТА ===")

    def _cleanup_old_logs(self):
        """Хранит только 5 последних логов, удаляя старые."""
        try:
            logs = sorted(self.log_dir.glob("session_*.log"), key=os.path.getmtime, reverse=True)
            for log in logs[5:]:
                log.unlink(missing_ok=True)
        except Exception as e:
            pass

    def info(self, msg: str):
        logging.info(msg)

    def warn(self, msg: str):
        logging.warning(msg)

    def err(self, msg: str):
        logging.error(msg)

    def hash_log(self, file_path: str, hash_val: str):
        logging.info(f"ХЭШ ИНТЕГРИТИ: {file_path} -> SHA256: {hash_val}")

    def read_logs_tail(self, lines_count=25) -> list:
        """Эффективное бинарное чтение логов с конца файла (не забивает ОЗУ)."""
        try:
            with open(self.log_file, "rb") as f:
                f.seek(0, os.SEEK_END)
                buffer = bytearray()
                lines = []
                block_size = 1024
                pos = f.tell()

                while pos > 0 and len(lines) <= lines_count:
                    read_size = min(block_size, pos)
                    pos -= read_size
                    f.seek(pos)
                    chunk = f.read(read_size)
                    buffer = bytearray(chunk) + buffer

                    if b'\n' in chunk:
                        lines = buffer.split(b'\n')

                # Декодируем последние N строк
                return [line.decode('utf-8', errors='replace').strip()
                        for line in lines[-lines_count:] if line.strip()]
        except Exception as e:
            return [f"Ошибка чтения лога: {e}"]

    def log_batch_result(self, hw_info: dict, total_size: int, write_speed: float, read_speed: float, corrupted_chunks: int, chunk_size: int):
        """Экспорт результатов тестирования партии флешек в Excel (CSV)."""
        if getattr(sys, 'frozen', False):
            base_dir = Path(sys.executable).parent
        else:
            base_dir = Path(os.path.abspath(__file__)).parent

        csv_path = base_dir / "DEEPDRIVE_BATCH_REPORT.csv"
        file_exists = csv_path.exists()

        try:
            with open(csv_path, mode='a', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f, delimiter=';')

                if not file_exists:
                    writer.writerow([
                        "Дата", "Время", "Метка ОС", "Контроллер (VID:PID)", "Серийный номер",
                        "Заявленный объем", "Потеряно (Фейк/Брак)", "Скорость Записи (МБ/с)",
                        "Скорость Чтения (МБ/с)", "ВЕРДИКТ"
                    ])

                lost_size = corrupted_chunks * chunk_size
                status = "БРАК / ФЕЙК" if corrupted_chunks > 0 else "ОТЛИЧНО (ОРИГИНАЛ)"

                writer.writerow([
                    datetime.now().strftime("%Y-%m-%d"),
                    datetime.now().strftime("%H:%M:%S"),
                    hw_info.get('vendor', 'Unknown'),
                    f"{hw_info.get('vid', '0000')}:{hw_info.get('pid', '0000')}",
                    hw_info.get('sn', 'Н/Д'),
                    fmt_size(total_size),
                    fmt_size(lost_size) if corrupted_chunks > 0 else "0 Б",
                    f"{write_speed:.1f}",
                    f"{read_speed:.1f}",
                    status
                ])
                self.info(f"Результат бизнес-теста записан в CSV: {status}")
        except Exception as e:
            self.err(f"Не удалось записать CSV лог: {e}")


class TaskContext:
    """Потокобезопасный контекст для передачи статуса между ядром и UI."""
    def __init__(self):
        self.cancel = False
        self.status = "Инициализация..."
        self.result = None
        self.error = None
        self._lock = threading.Lock()

    def update(self, msg: str):
        with self._lock:
            self.status = msg

    def get_status(self) -> str:
        with self._lock:
            return self.status


class Win32DiskIO:
    """Контекстный менеджер для безопасной блокировки тома на уровне Windows API."""
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    FSCTL_LOCK_VOLUME = 0x00090018
    FSCTL_UNLOCK_VOLUME = 0x0009001C
    FSCTL_DISMOUNT_VOLUME = 0x00090020

    def __init__(self, drive_path: str, read_only=False, force_write_blocker=False):
        self.path = drive_path
        self.access = self.GENERIC_READ if (read_only or force_write_blocker) else (self.GENERIC_READ | self.GENERIC_WRITE)
        self.handle = -1
        self.locked = False

    def __enter__(self):
        self.handle = ctypes.windll.kernel32.CreateFileW(
            self.path,
            self.access,
            self.FILE_SHARE_READ | self.FILE_SHARE_WRITE,
            None,
            self.OPEN_EXISTING,
            0,
            None
        )
        if self.handle == -1:
            raise OSError(f"Отказано в доступе к {self.path}. Нужны права Администратора.")
        return self

    def lock_and_dismount(self):
        """Жесткая блокировка тома, чтобы ОС не мешала записи/стиранию."""
        ret = ctypes.c_ulong(0)
        res_lock = ctypes.windll.kernel32.DeviceIoControl(
            self.handle, self.FSCTL_LOCK_VOLUME, None, 0, None, 0, ctypes.byref(ret), None
        )
        res_dismount = ctypes.windll.kernel32.DeviceIoControl(
            self.handle, self.FSCTL_DISMOUNT_VOLUME, None, 0, None, 0, ctypes.byref(ret), None
        )
        if res_lock:
            self.locked = True
        return res_lock and res_dismount

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.handle != -1:
            if self.locked:
                ret = ctypes.c_ulong(0)
                ctypes.windll.kernel32.DeviceIoControl(
                    self.handle, self.FSCTL_UNLOCK_VOLUME, None, 0, None, 0, ctypes.byref(ret), None
                )
            ctypes.windll.kernel32.CloseHandle(self.handle)


# =====================================================================
# МЕНЕДЖЕР ОБОРУДОВАНИЯ И БАЗА ДАННЫХ УСТРОЙСТВ
# =====================================================================

class HardwareManager:
    @staticmethod
    def get_system_drive_number() -> int:
        if sys.platform != 'win32': return 0
        windir = os.environ.get("WINDIR", "C:\\")
        drive_letter = windir[:2] + "\\"
        try:
            import wmi
            c = wmi.WMI()
            for p in c.Win32_LogicalDiskToPartition():
                if p.Dependent.DeviceID == windir[:2]:
                    for d in c.Win32_DiskDriveToDiskPartition():
                        if d.Dependent.DeviceID == p.Antecedent.DeviceID:
                            match = re.search(r'PHYSICALDRIVE(\\d+)', d.Antecedent.DeviceID)
                            if match: return int(match.group(1))
        except Exception:
            pass
        return 0

    @staticmethod
    def is_system_drive(d_num: int) -> bool:
        return d_num == HardwareManager.get_system_drive_number()


    """Отвечает за поиск, идентификацию и управление питанием USB-устройств."""

    @staticmethod
    def is_valid_drive_letter(letter: str) -> bool:
        return bool(re.match(r"^[A-Z]:$", letter.upper()))

    @staticmethod
    def get_combined_usb_drives() -> list:
        """Быстрый опрос WMI."""
        drives_list = []
        try:
            import wmi
            c = wmi.WMI()
            for disk in c.Win32_DiskDrive(InterfaceType="USB"):
                letters = []
                for dp in c.Win32_DiskDriveToDiskPartition():
                    if dp.Antecedent.DeviceID == disk.DeviceID:
                        for lp in c.Win32_LogicalDiskToPartition():
                            if lp.Antecedent.DeviceID == dp.Dependent.DeviceID:
                                letters.append(lp.Dependent.DeviceID)
                is_raw = len(letters) == 0
                label = ", ".join(letters) if letters else "RAW/UNINITIALIZED"

                match = re.search(r'PHYSICALDRIVE(\\d+)', disk.DeviceID)
                if match:
                    d_num = int(match.group(1))
                    size_val = int(disk.Size) if disk.Size else 0
                    drives_list.append({
                        "num": d_num,
                        "name": disk.Model,
                        "size": size_val,
                        "letter": letters[0].replace(':', '') if letters else None,
                        "is_raw": is_raw,
                        "display": f"[PHY_DRIVE_{d_num}] {label.ljust(18)} | {disk.Model} | {fmt_size(size_val)}"
                    })
        except Exception:
            pass
        return drives_list

    @staticmethod
    def get_hw_info(target: str) -> dict:
        info = {
            'd_num': None, 'size': 0, 'vendor': 'Неизвестное устройство',
            'sn': 'Н/Д', 'vid': '0000', 'pid': '0000', 'PNP': None,
            'ver': 'Н/Д', 'ro': False, 'bus': 'USB (Интерфейс не определен)'
        }
        if not target: return info

        try:
            import wmi
            c = wmi.WMI()

            d_num = -1
            if "Disk #" in target:
                d_num = int(target.split('#')[1])
            else:
                letter = target[0].upper() + ":"
                for p in c.Win32_LogicalDiskToPartition():
                    if p.Dependent.DeviceID == letter:
                        for d in c.Win32_DiskDriveToDiskPartition():
                            if d.Dependent.DeviceID == p.Antecedent.DeviceID:
                                match = re.search(r'PHYSICALDRIVE(\\d+)', d.Antecedent.DeviceID)
                                if match: d_num = int(match.group(1))

            if d_num != -1:
                for disk in c.Win32_DiskDrive(Index=d_num):
                    info['d_num'] = d_num
                    info['size'] = int(disk.Size) if disk.Size else 0
                    info['vendor'] = disk.Model.strip() if disk.Model else 'Unknown Device'
                    info['sn'] = disk.SerialNumber.strip() if disk.SerialNumber else 'N/A'
                    info['ver'] = disk.FirmwareRevision.strip() if disk.FirmwareRevision else 'N/A'
                    info['PNP'] = disk.PNPDeviceID

                    if disk.PNPDeviceID:
                        v_m = re.search(r'VID_([0-9A-F]{4})', disk.PNPDeviceID, re.I)
                        p_m = re.search(r'PID_([0-9A-F]{4})', disk.PNPDeviceID, re.I)
                        if v_m: info['vid'] = v_m.group(1).upper()
                        if p_m: info['pid'] = p_m.group(1).upper()

                    try:
                        c2 = wmi.WMI(namespace="root\\Microsoft\\Windows\\Storage")
                        for m_disk in c2.MSFT_PhysicalDisk(DeviceId=str(d_num)):
                            info['ro'] = m_disk.IsReadOnly
                    except Exception:
                        pass
        except Exception:
            pass

        return info

    def get_safe_path(self, target: str) -> str:
        """Превращает 'Disk #2' или 'F:' в корректный путь для Windows API."""
        if not target: return ""
        if "Disk #" in target:
            d_num = target.split('#')[1]
            return f"\\\\.\\PhysicalDrive{d_num}"
        # Если это буква (например F:), возвращаем формат тома
        return f"\\\\.\\{target[0]}:"


class LocalDB:
    """Локальная база данных USB ID для сопоставления VID/PID с производителями."""
    def __init__(self, ui_ref, logger):
        self.ui = ui_ref
        self.logger = logger
        self.vendors = {}
        self.devices = {}
        self.db_file = "usb.ids"

    def check_internet(self) -> bool:
        """Быстрая проверка доступности сети перед скачиванием БД."""
        try:
            urllib.request.urlopen("http://www.linux-usb.org", timeout=3)
            return True
        except Exception:
            return False

    def fetch_and_load(self, ctx=None):
        """Скачивает базу linux-usb.org, если её нет, и загружает в память."""
        def _log_status(msg, level="info"):
            if ctx: ctx.update(msg)
            else: self.ui.slow_print(f"  {msg}", level)

        if not os.path.exists(self.db_file):
            _log_status("[*] Проверка подключения для загрузки базы...", "info")
            if not self.check_internet():
                _log_status("[-] Нет интернета. Работаем без вендоров.", "warn")
                time.sleep(1)
            else:
                _log_status("[*] Загрузка usb.ids (linux-usb.org)...", "warn")
                try:
                    urllib.request.urlretrieve("http://www.linux-usb.org/usb.ids", self.db_file)
                    _log_status("[+] База успешно загружена!", "ok")
                except Exception as e:
                    self.logger.err(f"Ошибка загрузки БД: {e}")
                    _log_status("[-] Ошибка загрузки базы.", "err")
                    time.sleep(1)

        if os.path.exists(self.db_file):
            _log_status("[*] Индексация базы оборудования...", "info")
            try:
                with open(self.db_file, "r", encoding="utf-8", errors="ignore") as file:
                    current_vendor = None
                    for line in file:
                        clean_line = line.strip("\n")
                        if clean_line.startswith("#") or not clean_line.strip():
                            continue
                        if not clean_line.startswith("\t"):
                            parts = clean_line.strip().split("  ", 1)
                            if len(parts) == 2:
                                current_vendor = parts[0].lower()
                                self.vendors[current_vendor] = parts[1]
                        elif clean_line.startswith("\t") and not clean_line.startswith("\t\t"):
                            parts = clean_line.strip().split("  ", 1)
                            if len(parts) == 2 and current_vendor:
                                pid = parts[0].lower()
                                self.devices[f"{current_vendor}:{pid}"] = parts[1]
                _log_status("[OK] База USB.IDS готова", "ok")
            except Exception as e:
                self.logger.err(f"Ошибка парсинга БД: {traceback.format_exc()}")
                _log_status("[-] Ошибка чтения базы.", "err")

    def resolve(self, vid: str, pid: str) -> tuple:
        """Возвращает (Имя Вендора, Имя Устройства) по VID и PID."""
        vendor_name = self.vendors.get(vid.lower(), "НЕИЗВЕСТНЫЙ ПРОИЗВОДИТЕЛЬ")
        device_name = self.devices.get(f"{vid.lower()}:{pid.lower()}", "НЕИЗВЕСТНЫЙ КОНТРОЛЛЕР")
        return vendor_name, device_name


# =====================================================================
# НАСТРОЙКИ ПРИЛОЖЕНИЯ
# =====================================================================

class Settings:
    """Хранит пользовательские настройки в JSON (~APPDATA/DeepDrive/settings.json)."""
    CONFIG_DIR   = Path(os.environ.get('APPDATA', '.')) / 'DeepDrive'
    CONFIG_FILE  = CONFIG_DIR / 'settings.json'

    # Папка с пресетами будет создана рядом с исполняемым файлом программы
    def get_presets_dir(self):
        if getattr(sys, 'frozen', False):
            base_dir = Path(sys.executable).parent
        else:
            base_dir = Path(os.path.abspath(__file__)).parent
        presets_dir = base_dir / "DeepDrive_Presets"
        presets_dir.mkdir(parents=True, exist_ok=True)
        return presets_dir

    DEFAULTS = {
        # -- ЦВЕТА (RGB) --
        'accent_r':              36,
        'accent_g':             228,
        'accent_b':             213,
        'bg_r':                   5,
        'bg_g':                   5,
        'bg_b':                   8,
        'text_r':               210,
        'text_g':               210,
        'text_b':               210,
        'dim_r':                 90,
        'dim_g':                 90,
        'dim_b':                 90,
        'warn_r':               255,
        'warn_g':               200,
        'warn_b':                 0,
        'err_r':                255,
        'err_g':                 60,
        'err_b':                 60,
        'ok_r':                  80,
        'ok_g':                 230,
        'ok_b':                 120,

        # -- INTERFACE --
        'slow_print_delay':   0.003,
        'header_width':          72,
        'header_char':          '-',
        'progress_bar_width':    28,
        'progress_bar_fill':    '|',
        'progress_bar_empty':   '.',
        'menu_pointer':         '>>',
        'menu_numbers':          True,

        # -- PERFORMANCE --
        'chunk_size_kb':        512,
        'read_buffer_mb':         4,
        'carver_max_file_mb':    64,
        'speed_test_passes':      3,
        'ps_timeout_sec':        15,
        'spinner_fps':           10,

        # -- LOGGING --
        'log_max_count':          5,
        'log_tail_lines':        20,
        'log_level':          'INFO',
        'log_timestamps':      True,
        'csv_delimiter':         ';',

        # -- БЕЗОПАСНОСТЬ --
        'write_block_default':  True,
        'confirm_wipe_phrase': 'DOD',
        'confirm_burn_phrase': 'BURN',
        'auto_hash_on_dump':   True,
        'bsod_auto_return':   False,
        'bsod_scan_tip':       True,
        'yara_rule_file':   'Rule.yar',
        'dod_passes':             3,

        # -- ОТЛАДКА --
        'dev_verbose_errors':  False,
        'dev_show_ps_output':  False,
        'dev_disable_bsod':    False,
        'dev_fake_admin':      False,
        'dev_dry_run':         False,
        'dev_perf_timings':    False,
    }


    # Ключи, которые принадлежат отдельным группам (не DEFAULTS)
    _META_FIELDS    = {"_meta", "_menu_labels", "_hotkeys", "_disabled_items"}

    # Ключи по типу пресета
    PRESET_KEYS = {
        "theme": [
            "accent_r","accent_g","accent_b",
            "bg_r","bg_g","bg_b",
            "text_r","text_g","text_b",
            "dim_r","dim_g","dim_b",
            "warn_r","warn_g","warn_b",
            "err_r","err_g","err_b",
            "ok_r","ok_g","ok_b",
            "theme","header_char","header_title_prefix",
            "progress_bar_fill","progress_bar_empty",
            "menu_pointer","blink_enabled","compact_header",
        ],
        "performance": [
            "chunk_size_kb","read_buffer_mb","carver_max_file_mb",
            "speed_test_passes","ps_timeout_sec","spinner_fps",
            "thread_pool_size","slow_print_delay",
        ],
        "security": [
            "write_block_default","confirm_wipe_phrase","confirm_burn_phrase",
            "auto_hash_on_dump","dod_passes","require_admin_for_hex",
            "confirm_format","exit_confirm",
        ],
        "full": None,  # None = все ключи из DEFAULTS
    }

    def __init__(self):
        self.data = dict(self.DEFAULTS)
        self.menu_labels: dict = {}     # {str(idx): label} — overrides для главного меню
        self.hotkeys: dict = {}         # {str(idx): key} — override горячих клавиш
        self.disabled_items: list = []  # [idx] — скрытые пункты главного меню
        self.load()

    def load(self):
        try:
            if self.CONFIG_FILE.exists():
                raw = json.loads(self.CONFIG_FILE.read_text(encoding='utf-8'))
                # Переносим только известные ключи (миграция)
                for k, v in raw.items():
                    if k in self.DEFAULTS:
                        self.data[k] = v
                # Загружаем мета-поля
                self.menu_labels   = raw.get('_menu_labels', {})
                self.hotkeys       = raw.get('_hotkeys', {})
                self.disabled_items= raw.get('_disabled_items', [])
        except Exception:
            pass

    def save(self):
        try:
            self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            payload = dict(self.data)
            if self.menu_labels:    payload['_menu_labels']    = self.menu_labels
            if self.hotkeys:        payload['_hotkeys']        = self.hotkeys
            if self.disabled_items: payload['_disabled_items'] = self.disabled_items
            self.CONFIG_FILE.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding='utf-8'
            )
        except Exception:
            pass

    def get(self, key, default=None):
        return self.data.get(key, default if default is not None else self.DEFAULTS.get(key))

    def set(self, key, value):
        self.data[key] = value

    def reset_to_defaults(self):
        """Полный сброс всех параметров к заводским значениям."""
        self.data = dict(self.DEFAULTS)
        self.menu_labels = {}
        self.hotkeys = {}
        self.disabled_items = []
        self.save()

    # ---- Кастомные пресеты (Отдельные файлы) --------------------------------
    def build_preset_data(self, preset_type: str, extras: dict = None) -> dict:
        """Строит словарь данных пресета нужного типа."""
        keys = self.PRESET_KEYS.get(preset_type)
        if keys is None:  # full
            payload = dict(self.data)
        else:
            payload = {k: self.data[k] for k in keys if k in self.data}
        if extras:
            payload.update(extras)
        return payload

    def save_custom_preset(self, name: str, preset_type: str = 'full',
                           description: str = '', author: str = '@Machinist',
                           menu_labels: dict = None, hotkeys: dict = None,
                           disabled_items: list = None):
        """Сохранить пресет. preset_type: 'theme'|'performance'|'security'|'full'."""
        presets_dir = self.get_presets_dir()
        safe_name = "".join(c for c in name if c.isalnum() or c in " _-")
        if not safe_name:
            return
        payload = self.build_preset_data(preset_type)
        payload['_meta'] = {
            'name':        name,
            'description': description,
            'author':      author,
            'type':        preset_type,
            'version':     '1',
            'created':     datetime.now().strftime('%Y-%m-%d %H:%M'),
        }
        if menu_labels:    payload['_menu_labels']    = menu_labels
        if hotkeys:        payload['_hotkeys']        = hotkeys
        if disabled_items: payload['_disabled_items'] = disabled_items
        file_path = presets_dir / f"{safe_name}.json"
        try:
            file_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding='utf-8'
            )
        except Exception:
            pass

    def load_custom_preset(self, name: str) -> tuple:
        """Загрузить пресет. Возвращает (ok, meta, warnings). Безопасная миграция."""
        presets_dir = self.get_presets_dir()
        safe_name = "".join(c for c in name if c.isalnum() or c in " _-")
        file_path = presets_dir / f"{safe_name}.json"
        if not file_path.exists():
            return False, {}, []
        try:
            raw = json.loads(file_path.read_text(encoding='utf-8'))
        except Exception as e:
            return False, {}, [f"Ошибка чтения JSON: {e}"]

        meta = raw.get('_meta', {})
        warnings = []
        applied = 0

        for k, v in raw.items():
            if k in self._META_FIELDS:
                continue  # обрабатываем отдельно
            if k in self.DEFAULTS:
                self.data[k] = v
                applied += 1
            else:
                warnings.append(f"Неизвестный ключ '{k}' — пропущен")

        # Применяем мета-поля
        if '_menu_labels' in raw:
            self.menu_labels = raw['_menu_labels']
        if '_hotkeys' in raw:
            self.hotkeys = raw['_hotkeys']
        if '_disabled_items' in raw:
            self.disabled_items = raw['_disabled_items']

        self.save()
        return True, meta, warnings

    def get_preset_meta(self, name: str) -> dict:
        """Прочитать только _meta пресета без его применения."""
        presets_dir = self.get_presets_dir()
        safe_name = "".join(c for c in name if c.isalnum() or c in " _-")
        file_path = presets_dir / f"{safe_name}.json"
        try:
            raw = json.loads(file_path.read_text(encoding='utf-8'))
            return raw.get('_meta', {'name': name, 'type': 'unknown'})
        except Exception:
            return {'name': name, 'type': 'unknown'}

    def ensure_factory_reset_preset(self):
        """Создать _FACTORY_RESET.json если не существует."""
        presets_dir = self.get_presets_dir()
        frp = presets_dir / "_FACTORY_RESET.json"
        if not frp.exists():
            payload = dict(self.DEFAULTS)
            payload['_meta'] = {
                'name': 'Factory Reset',
                'description': 'Полный сброс к заводским настройкам DeepDrive.',
                'author': '@Machinist',
                'type': 'full',
                'version': '1',
                'created': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'protected': True,
            }
            try:
                frp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
            except Exception:
                pass

    def list_custom_presets(self) -> list:
        """Вернуть список имён кастомных пресетов (без .json)."""
        presets_dir = self.get_presets_dir()
        presets = []
        try:
            for file in presets_dir.glob("*.json"):
                presets.append(file.stem)
        except Exception:
            pass
        return sorted(presets)

    def delete_custom_preset(self, name: str) -> bool:
        """Удалить файл пресета."""
        presets_dir = self.get_presets_dir()
        safe_name = "".join(c for c in name if c.isalnum() or c in " _-")
        file_path = presets_dir / f"{safe_name}.json"
        if file_path.exists():
            try:
                file_path.unlink()
                return True
            except Exception:
                pass
        return False


    def accent_ansi_normal(self) -> str:
        r, g, b = self.get('accent_r'), self.get('accent_g'), self.get('accent_b')
        return f"\033[38;2;{r};{g};{b}m"

    def accent_bg_ansi(self) -> str:
        br, bg, bb = self.get('bg_r'), self.get('bg_g'), self.get('bg_b')
        r, g, b = self.get('accent_r'), self.get('accent_g'), self.get('accent_b')
        dr, dg, db = max(br, r // 4), max(bg, g // 4), max(bb, b // 4)
        return f"\033[48;2;{dr};{dg};{db}m"

class BiosTheme:
    """Минималистичный тёмный UI — DeepDrive V2.2."""
    def __init__(self):
        if os.name == 'nt':
            os.system('')  # Включает ANSI-коды в консоли Windows
        self.settings = Settings()
        self._rebuild_colors()

    def _rebuild_colors(self):
        s = self.settings
        def _rgb(r,g,b): return f"\033[38;2;{r};{g};{b}m"
        def _bg(r,g,b):  return f"\033[48;2;{r};{g};{b}m"

        ar, ag, ab = s.get('accent_r'), s.get('accent_g'), s.get('accent_b')
        br, bg, bb = s.get('bg_r'), s.get('bg_g'), s.get('bg_b')
        tr, tg, tb = s.get('text_r'), s.get('text_g'), s.get('text_b')
        dr, dg, db = s.get('dim_r'),  s.get('dim_g'),  s.get('dim_b')
        wr, wg, wb = s.get('warn_r'), s.get('warn_g'), s.get('warn_b')
        er, eg, eb = s.get('err_r'),  s.get('err_g'),  s.get('err_b')
        or_, og, ob = s.get('ok_r'),  s.get('ok_g'),   s.get('ok_b')

        self.colors = {
            "bg":        _bg(br, bg, bb),
            "text":      _rgb(tr, tg, tb),
            "highlight": f"\033[1m{_rgb(ar, ag, ab)}",
            "warn":      _rgb(wr, wg, wb),
            "err":       _rgb(er, eg, eb),
            "select":    f"{_bg(max(0,ar//3), max(0,ag//3), max(0,ab//3))}{_rgb(ar, ag, ab)}",
            "ok":        _rgb(or_, og, ob),
            "info":      _rgb(ar, ag, ab),
            "dim":       _rgb(dr, dg, db),
            "reset":     "\033[0m",
        }


    def set_accent_rgb(self, r: int, g: int, b: int):
        """Устанавливает новый RGB-акцент, сохраняет и применяет немедленно."""
        r, g, b = max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b))
        self.settings.set('accent_r', r)
        self.settings.set('accent_g', g)
        self.settings.set('accent_b', b)
        self.settings.save()
        self._rebuild_colors()

    def apply_bg(self):
        """Применяет фон согласно настройкам."""
        sys.stdout.write(f"{self.colors['bg']}{self.colors['text']}\033[2J\033[3J\033[H")
        sys.stdout.flush()

    def clear(self):
        sys.stdout.write("\033[2J\033[3J\033[H")
        sys.stdout.flush()

    def c(self, text: str, style="text") -> str:
        """Обёртка для применения цвета к строке."""
        target_color = self.colors.get(style, self.colors['text'])
        return f"{target_color}{text}{self.colors['text']}{self.colors['bg']}"

    def slow_print(self, text: str, style="text", delay=0.003):
        """Эффект 'печатной машинки' (ускоренный)."""
        sys.stdout.write(self.c("", style))
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print(self.c("", "text"))

    def pause(self):
        print(self.c("\n  [ нажмите любую клавишу ]", "dim"))
        msvcrt.getch()

    def progress_bar(self, percentage: float, width: int = 28) -> str:
        """Цветная полоса прогресса: зелёный >75%, жёлтый 25-75%, красный <25%."""
        percentage = max(0.0, min(100.0, percentage))
        filled = int(width * (percentage / 100))
        bar_fill = '|' * filled + '.' * (width - filled)
        if percentage >= 75:
            color = "\033[1;91m"   # красный — много занято
        elif percentage >= 25:
            color = "\033[1;93m"   # жёлтый — умеренно
        else:
            color = "\033[1;92m"   # зелёный — почти пусто
        reset = f"{self.colors['text']}{self.colors['bg']}"
        return f"[{color}{bar_fill}{reset}] {percentage:5.1f}%"

    def color_speed(self, speed_mbps: float) -> str:
        """Возвращает скорость с цветовым кодированием: красный/жёлтый/зелёный."""
        val = f"{speed_mbps:.1f} МБ/с"
        if speed_mbps < 5:
            return self.c(val, "err")
        elif speed_mbps < 25:
            return self.c(val, "warn")
        else:
            return self.c(val, "ok")

    def header(self, title: str, is_restricted=False, write_block=False):
        """Минималистичная шапка программы."""
        self.clear()
        mode = self.c("ПОЛЬЗОВАТЕЛЬ", "err") if is_restricted else self.c("АДМИНИСТРАТОР", "ok")
        wb   = self.c("БЛОК: ВКЛ",  "ok")  if write_block    else self.c("БЛОК: ВЫКЛ",  "err")

        sep = self.c("  " + "─" * 72, "dim")
        print(f"\n  {self.c('DEEPDRIVE', 'highlight')}  {self.c(APP_VERSION, 'info')}  "
              f"{self.c('·', 'dim')}  {self.c('by Machinist', 'dim')}")
        print(sep)
        print(f"  {self.c('ЦЕЛЬ:', 'dim')} {self.c(title, 'highlight')}   "
              f"{self.c('ПРАВА:', 'dim')} {mode}   "
              f"{self.c('WRITE-BLOCKER:', 'dim')} {wb}")
        print(sep + "\n")

    def run_task(self, title: str, worker_func, danger_level=0, *args):
        """Запустить задачу в пуле потоков с отображением статуса и ESC-отменой."""
        import concurrent.futures

        self.slow_print(f"  ▸  {title}...\n", "info")

        if danger_level == 2:
            print(self.c("  ⚠  КРИТИЧЕСКАЯ ОПЕРАЦИЯ — НЕ ИЗВЛЕКАЙТЕ НАКОПИТЕЛЬ!", "err"))
            print(self.c("     Риск уничтожения файловой системы.", "err"))
        elif danger_level == 1:
            print(self.c("  ⚠  Идёт активное чтение. Не извлекайте диск.", "warn"))

        print(self.c("  ·  ESC — экстренная отмена.\n", "dim"))

        ctx = TaskContext()

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(worker_func, ctx, *args)
            try:
                while not future.done():
                    if msvcrt.kbhit() and msvcrt.getch() == b'\x1b':
                        ctx.cancel = True
                    status_text = ctx.get_status()
                    sys.stdout.write(f"\r  │ {status_text}".ljust(90))
                    sys.stdout.flush()
                    time.sleep(0.05)
            except KeyboardInterrupt:
                ctx.cancel = True

            future.result()

        sys.stdout.write(f"\r  │ {ctx.get_status()}".ljust(90) + "\n")

        if ctx.error:
            print(self.c(f"\n  ✗  ОШИБКА: {ctx.error}", "err"))
        elif ctx.cancel:
            print(self.c("\n  ⚠  ОПЕРАЦИЯ ОТМЕНЕНА ПОЛЬЗОВАТЕЛЕМ.", "warn"))
        else:
            if ctx.result:
                print(self.c(f"\n  ✓  {ctx.result}", "ok"))
            else:
                print(self.c("\n  ✓  ОПЕРАЦИЯ УСПЕШНО ЗАВЕРШЕНА.", "ok"))

    def menu(self, title: str, options: list, current_target: str, restricted: bool, write_block: bool) -> int:
        """Интерактивное меню: стрелки + цифровой быстрый выбор."""
        current_idx = 0
        last_idx = -1

        while True:
            # Защита от внезапного извлечения устройства
            if current_target:
                try:
                    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                    drive_letter_idx = ord(current_target[0].upper()) - 65
                    if 0 <= drive_letter_idx <= 25 and not (bitmask & (1 << drive_letter_idx)):
                        return -999
                except Exception:
                    pass

            if current_idx != last_idx:
                self.header(current_target if current_target else "НЕ ВЫБРАНА", restricted, write_block)
                print(self.c(f"  {title}:\n", "highlight"))

                for i, option_text in enumerate(options):
                    if i == current_idx:
                        print(f"    {self.c('▸ ' + option_text, 'select')}")
                    else:
                        print(f"      {self.c(option_text, 'text')}")

                print(self.c("\n  " + "─" * 72, "dim"))
                print(f"  {self.c('↑↓ навигация  ·  ENTER выбор  ·  ESC назад  ·  0-9 быстрый выбор', 'dim')}")
                last_idx = current_idx

            if msvcrt.kbhit():
                key = msvcrt.getch()
                if key in (b'\xe0', b'\x00'):
                    arrow = msvcrt.getch()
                    if arrow == b'H':   # Вверх
                        current_idx = (current_idx - 1) % len(options)
                    elif arrow == b'P': # Вниз
                        current_idx = (current_idx + 1) % len(options)
                elif key == b'\r':   # Enter
                    return current_idx
                elif key == b'\x1b': # Esc
                    return -1
                elif key.isdigit():  # Быстрый выбор цифрой
                    digit = int(key.decode())
                    # Проверяем remapped hotkeys
                    mapped = self.settings.hotkeys.get(str(digit))
                    if mapped is not None:
                        target = int(mapped)
                        if 0 <= target < len(options):
                            return target
                    elif digit < len(options):
                        return digit
            else:
                time.sleep(0.05)


# =====================================================================
# ДОПОЛНИТЕЛЬНЫЕ ИНСТРУМЕНТЫ (HEX VIEWER И ПРОЧЕЕ)
# =====================================================================

class HexViewer:
    """Интерактивный просмотрщик сырых секторов (RAW HEX)."""
    def __init__(self, ui, disk_path, disk_size):
        self.ui = ui
        self.path = disk_path
        self.size = disk_size
        self.sector_size = 512
        self.current_sector = 0

    def view(self):
        try:
            with open(self.path, "rb") as disk:
                while True:
                    disk.seek(self.current_sector * self.sector_size)
                    data = disk.read(self.sector_size)

                    self.ui.clear()
                    sep = self.ui.c("  " + "─" * 72, "dim")
                    print(self.ui.c(f"\n  HEX VIEWER  ·  {self.path}  ·  Сектор #{self.current_sector}", "highlight"))
                    print(sep)
                    print(self.ui.c("  OFFSET   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   ASCII", "info"))
                    print(sep)

                    if not data:
                        print(self.ui.c("\n  ⚠  Конец диска или ошибка чтения.", "err"))
                    else:
                        for i in range(0, len(data), 16):
                            chunk = data[i:i+16]
                            hex_str = " ".join(f"{b:02X}" for b in chunk)
                            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                            print(f"  {i:04X}     {hex_str:<47}   {self.ui.c(ascii_str, 'warn')}")

                    print(sep)
                    print(f"  {self.ui.c('← → сектор  ·  G перейти к сектору  ·  ESC выход', 'dim')}")

                    while True:
                        if msvcrt.kbhit():
                            key = msvcrt.getch()
                            if key in (b'\xe0', b'\x00'):
                                arrow = msvcrt.getch()
                                if arrow == b'K':   # Влево
                                    self.current_sector = max(0, self.current_sector - 1)
                                    break
                                elif arrow == b'M': # Вправо
                                    max_sector = (self.size // self.sector_size) - 1 if self.size else 999999
                                    self.current_sector = min(self.current_sector + 1, max_sector)
                                    break
                            elif key in (b'g', b'G'):
                                # Goto Sector
                                self.ui.clear()
                                print(self.ui.c(f"\n  HEX VIEWER  ·  Переход к сектору\n", "highlight"))
                                try:
                                    raw = input(self.ui.c("  Введите номер сектора (dec или 0xHEX) >> ", "info")).strip()
                                    target = int(raw, 0)
                                    max_sector = (self.size // self.sector_size) - 1 if self.size else 999999
                                    self.current_sector = max(0, min(target, max_sector))
                                except ValueError:
                                    pass
                                break
                            elif key == b'\x1b':
                                return
                        time.sleep(0.05)
        except PermissionError:
            print(self.ui.c("\n  ✗  Нет доступа. Запустите от имени Администратора.", "err"))
            self.ui.pause()



# =====================================================================
# ЯДРО БИЗНЕС-ЛОГИКИ (FORENSIC & RUFUS ENGINE)
# =====================================================================

def protective_shell(func):
    """Декоратор для перехвата системных сбоев (возвращен из V1.6)."""
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except PermissionError:
            print(self.ui.c("\n  [-] СИСТЕМНАЯ БЛОКИРОВКА: Необходимы права Администратора.", "err"))
            self.logger.err(f"Отказ в доступе в функции {func.__name__}")
        except Exception as e:
            err_msg = f"ЗАЩИТНАЯ ОБОЛОЧКА ПЕРЕХВАТИЛА СБОЙ ({func.__name__}): {e}"
            print(self.ui.c(f"\n  [-] {err_msg}", "err"))
            self.logger.err(traceback.format_exc())
    return wrapper


class CoreEngine:
    """Главный движок, содержащий всю логику криминалистики и работы с дисками."""
    def __init__(self, ui, logger, db):
        self.ui = ui
        self.logger = logger
        self.db = db
        self.write_block = True

        # Расширенный словарь сигнатур (из V1.6 + добавлены новые)
        self.signatures = [
            (b'\xFF\xD8\xFF', b'\xFF\xD9', "jpg"),
            (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\x49\x45\x4E\x44\xAE\x42\x60\x82', "png"),
            (b'%PDF-', b'%%EOF', "pdf"),
            (b'\x50\x4B\x03\x04', b'\x50\x4B\x05\x06', "zip_docx_xlsx"),
            (b'\x52\x61\x72\x21\x1A\x07\x00', b'\xC4\x3D\x7B\x00\x40\x07\x00', "rar"),
            (b'\x37\x7A\xBC\xAF\x27\x1C', None, "7z"),
            (b'\x49\x44\x33', None, "mp3"),
            (b'\x00\x00\x00\x18\x66\x74\x79\x70', None, "mp4"),
            (b'\x52\x49\x46\x46', b'\x41\x56\x49\x20', "avi"),
            (b'\x4D\x5A', None, "exe_dll"),
            (b'\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00', None, "sqlite"),
            (b'\x4F\x67\x67\x53', None, "ogg"),
            (b'\x42\x4D', None, "bmp"),
            (b'\x49\x49\x2A\x00', None, "tiff_le"),
            (b'\x4D\x4D\x00\x2A', None, "tiff_be"),
            (b'\x7B\x5C\x72\x74\x66\x31', b'\x7D', "rtf"),
            (b'\x43\x44\x30\x30\x31', None, "iso")
        ]

    # --- ИНФОРМАЦИЯ И АНАЛИТИКА ---

    @protective_shell
    def show_info(self, hw, v_db, p_db):
        """Отрисовка расширенной аппаратной сводки с детальным анализом."""
        vendor   = hw.get('vendor', 'Неизвестное устройство')
        sn       = hw.get('sn', 'Н/Д') or 'Н/Д'
        firmware = hw.get('ver', 'Н/Д') or 'Н/Д'
        size_b   = hw.get('size', 0)
        used_b   = hw.get('used_bytes', 0)
        total_gb = size_b / (1024**3) if size_b > 0 else 0

        ro_status  = self.ui.c('ЗАБЛОКИРОВАН', 'err') if hw.get('ro') else self.ui.c('ОТКРЫТ', 'ok')
        d_num_str  = f"PhysicalDrive{hw['d_num']}" if hw.get('d_num') is not None else "Н/Д"
        part_style = hw.get('part_style', 'RAW')
        part_count = hw.get('part_count', 0)
        bus_str    = hw.get('bus', 'USB (Интерфейс не определен)')
        vid        = str(hw.get('vid', '0000')).zfill(4)
        pid        = str(hw.get('pid', '0000')).zfill(4)
        health     = hw.get('smart_health', 'Unknown')
        pnp_id     = hw.get('PNP', '')

        # Новые поля из расширенного PS-запроса
        read_errors  = hw.get('read_errors')
        write_errors = hw.get('write_errors')
        power_on_hrs = hw.get('power_on_hrs')
        wear_val     = hw.get('wear')
        media_type   = hw.get('media_type', 'Unknown')
        op_status    = hw.get('op_status', 'Unknown')
        fs_type      = hw.get('fs_type', '')

        # ── Теоретическая скорость шины ──
        bus_speed_map = {
            "USB 1.0": "1.5 Мбит/с",  "USB 1.1": "12 Мбит/с",
            "USB 2.0": "480 Мбит/с",  "USB 3.0": "5 Гбит/с",
            "USB 3.1": "10 Гбит/с",   "USB 3.2": "20 Гбит/с",
        }
        bus_speed = next((v for k, v in bus_speed_map.items() if k in bus_str), "Н/Д")

        # ═══════════════════════════════════════════════════════
        # БЛОК 1: ОЦЕНКА КОНТРОЛЛЕРА (макс. 10)
        # ═══════════════════════════════════════════════════════
        ctrl_score = 0
        ctrl_notes = []

        vid_known = vid not in ('0000', 'ffff')
        pid_known = pid not in ('0000', 'ffff')
        if vid_known:
            ctrl_score += 2
            ctrl_notes.append(self.ui.c(f"✓ VID: 0x{vid} — идентифицирован", 'ok'))
        else:
            ctrl_notes.append(self.ui.c("✗ VID: 0x0000 — не определён (подозрительно)", 'err'))

        if pid_known:
            ctrl_score += 2
            ctrl_notes.append(self.ui.c(f"✓ PID: 0x{pid} — идентифицирован", 'ok'))
        else:
            ctrl_notes.append(self.ui.c("✗ PID: не определён — устройство нестандартно", 'warn'))

        v_db_known = v_db and 'НЕИЗВЕСТНЫЙ' not in v_db and len(v_db) > 3
        if v_db_known:
            ctrl_score += 2
            ctrl_notes.append(self.ui.c(f"✓ Производитель в базе: {v_db}", 'ok'))
        else:
            ctrl_notes.append(self.ui.c("✗ Производитель отсутствует в USB.IDS", 'warn'))

        p_db_known = p_db and 'Универсальный' not in p_db and len(p_db) > 5
        if p_db_known:
            ctrl_score += 2
            ctrl_notes.append(self.ui.c(f"✓ Модель в базе: {p_db[:45]}", 'ok'))
        else:
            ctrl_notes.append(self.ui.c("~ Модель: универсальный/неизвестный контроллер", 'dim'))

        # PNP-путь (наличие = контроллер нормально определился в ОС)
        if pnp_id and len(pnp_id) > 10:
            ctrl_score += 1
            ctrl_notes.append(self.ui.c("✓ PnP Device ID: драйвер определён штатно", 'ok'))
        else:
            ctrl_notes.append(self.ui.c("✗ PnP Device ID: путь не определён", 'warn'))

        # OperationalStatus
        op_lower = str(op_status).lower()
        if 'online' in op_lower or 'ok' in op_lower:
            ctrl_score += 1
            ctrl_notes.append(self.ui.c(f"✓ Статус ОС: {op_status} (работоспособен)", 'ok'))
        elif 'offline' in op_lower or 'degraded' in op_lower:
            ctrl_notes.append(self.ui.c(f"✗ Статус ОС: {op_status} — деградация!", 'err'))
        else:
            ctrl_notes.append(self.ui.c(f"~ Статус ОС: {op_status}", 'dim'))

        ctrl_bar = self.ui.progress_bar(ctrl_score * 10, 20)

        # ═══════════════════════════════════════════════════════
        # БЛОК 2: ОЦЕНКА НАДЁЖНОСТИ (макс. 10)
        # ═══════════════════════════════════════════════════════
        rel_score = 0
        rel_notes = []
        h_lower = health.lower()

        # SMART Health
        if h_lower == 'healthy':
            rel_score += 3
            rel_notes.append(self.ui.c("✓ S.M.A.R.T: Здоров (Healthy)", 'ok'))
        elif h_lower == 'warning':
            rel_score += 1
            rel_notes.append(self.ui.c("⚠ S.M.A.R.T: Предупреждение — скоро может отказать!", 'warn'))
        elif h_lower == 'unhealthy':
            rel_notes.append(self.ui.c("✗ S.M.A.R.T: НЕИСПРАВЕН — требуется замена!", 'err'))
        else:
            rel_score += 1
            rel_notes.append(self.ui.c("~ S.M.A.R.T: нет данных (типично для USB)", 'dim'))

        # Температура
        temp = hw.get('smart_temp')
        if temp:
            temp_val = int(temp)
            if temp_val <= 35:
                rel_score += 1
                rel_notes.append(self.ui.c(f"✓ Температура: {temp_val}°C (холодный / норма)", 'ok'))
            elif temp_val <= 45:
                rel_notes.append(self.ui.c(f"⚠ Температура: {temp_val}°C (умеренный нагрев)", 'warn'))
            elif temp_val <= 55:
                rel_notes.append(self.ui.c(f"⚠ Температура: {temp_val}°C (горячий!)", 'warn'))
            else:
                rel_notes.append(self.ui.c(f"✗ Температура: {temp_val}°C (ПЕРЕГРЕВ! Риск потери данных!)", 'err'))
        else:
            rel_score += 1
            rel_notes.append(self.ui.c("~ Температура: датчик отсутствует (стандарт для USB)", 'dim'))

        # Ошибки чтения
        if read_errors is not None:
            re_val = int(read_errors)
            if re_val == 0:
                rel_score += 1
                rel_notes.append(self.ui.c("✓ Ошибки чтения: 0 (идеально)", 'ok'))
            elif re_val < 100:
                rel_notes.append(self.ui.c(f"⚠ Ошибки чтения: {re_val} (допустимо, наблюдать)", 'warn'))
            else:
                rel_notes.append(self.ui.c(f"✗ Ошибки чтения: {re_val} (критически много!)", 'err'))
        else:
            rel_notes.append(self.ui.c("~ Ошибки чтения: счётчик недоступен", 'dim'))

        # Ошибки записи
        if write_errors is not None:
            we_val = int(write_errors)
            if we_val == 0:
                rel_score += 1
                rel_notes.append(self.ui.c("✓ Ошибки записи: 0 (идеально)", 'ok'))
            elif we_val < 50:
                rel_notes.append(self.ui.c(f"⚠ Ошибки записи: {we_val} (начался износ)", 'warn'))
            else:
                rel_notes.append(self.ui.c(f"✗ Ошибки записи: {we_val} (высокий показатель!)", 'err'))
        else:
            rel_notes.append(self.ui.c("~ Ошибки записи: счётчик недоступен", 'dim'))

        # Износ NAND (Wear — процент 0-100, 0 = новый)
        if wear_val is not None:
            w_int = int(wear_val)
            if w_int <= 10:
                rel_score += 1
                rel_notes.append(self.ui.c(f"✓ Износ NAND: {w_int}% (как новый)", 'ok'))
            elif w_int <= 50:
                rel_notes.append(self.ui.c(f"⚠ Износ NAND: {w_int}% (умеренный)", 'warn'))
            elif w_int <= 80:
                rel_notes.append(self.ui.c(f"⚠ Износ NAND: {w_int}% (значительный!)", 'warn'))
            else:
                rel_notes.append(self.ui.c(f"✗ Износ NAND: {w_int}% (критический! Замена!)", 'err'))
        else:
            rel_notes.append(self.ui.c("~ Износ NAND: данные недоступны", 'dim'))

        # Время работы
        if power_on_hrs is not None:
            poh = int(power_on_hrs)
            days = poh // 24
            if poh < 5000:
                rel_score += 1
                rel_notes.append(self.ui.c(f"✓ Наработка: {poh} часов ({days} дней) — малый пробег", 'ok'))
            elif poh < 20000:
                rel_notes.append(self.ui.c(f"~ Наработка: {poh} часов ({days} дней) — средний пробег", 'dim'))
            elif poh < 40000:
                rel_notes.append(self.ui.c(f"⚠ Наработка: {poh} часов ({days} дней) — большой пробег", 'warn'))
            else:
                rel_notes.append(self.ui.c(f"✗ Наработка: {poh} часов ({days} дней) — ветеран!", 'err'))
        else:
            rel_notes.append(self.ui.c("~ Наработка: счётчик часов недоступен", 'dim'))

        # Серийный номер
        if sn and sn != 'Н/Д' and len(sn) >= 8:
            rel_score += 1
            rel_notes.append(self.ui.c(f"✓ С/Н: {sn[:20]}{'…' if len(sn)>20 else ''} ({len(sn)} символов)", 'ok'))
        elif sn and sn != 'Н/Д':
            rel_notes.append(self.ui.c(f"⚠ С/Н: {sn} (подозрительно короткий)", 'warn'))
        else:
            rel_notes.append(self.ui.c("✗ Серийный номер: отсутствует (подделка?)", 'warn'))

        # Прошивка
        if firmware and firmware != 'Н/Д':
            rel_notes.append(self.ui.c(f"✓ Прошивка: {firmware}", 'ok'))
        else:
            rel_notes.append(self.ui.c("~ Прошивка: версия недоступна", 'dim'))

        rel_bar = self.ui.progress_bar(rel_score * 10, 20)

        # ═══════════════════════════════════════════════════════
        # БЛОК 3: ОЦЕНКА СКОРОСТИ И ЁМКОСТИ (макс. 10)
        # ═══════════════════════════════════════════════════════
        spd_score = 0
        spd_notes = []

        # Интерфейс USB
        if 'USB 3.2' in bus_str:
            spd_score += 3
            spd_notes.append(self.ui.c("✓ Шина: USB 3.2 Gen2x2 SuperSpeed+ (до 20 Гбит/с)", 'ok'))
        elif 'USB 3.1' in bus_str:
            spd_score += 3
            spd_notes.append(self.ui.c("✓ Шина: USB 3.1 SuperSpeed+ (до 10 Гбит/с)", 'ok'))
        elif 'USB 3.0' in bus_str or '3.x' in bus_str or 'SuperSpeed' in bus_str:
            spd_score += 2
            spd_notes.append(self.ui.c("✓ Шина: USB 3.0 SuperSpeed (до 5 Гбит/с)", 'ok'))
        elif 'USB 2.0' in bus_str or '2.0' in bus_str:
            spd_score += 1
            spd_notes.append(self.ui.c("~ Шина: USB 2.0 Hi-Speed (480 Мбит/с) — устаревший", 'warn'))
        elif 'USB 1.1' in bus_str:
            spd_notes.append(self.ui.c("✗ Шина: USB 1.1 (12 Мбит/с) — неприемлемо медленный!", 'err'))
        else:
            spd_score += 1
            spd_notes.append(self.ui.c("~ Шина: версия USB не определена", 'dim'))

        # Тип носителя (SSD / HDD / Removable)
        mt_lower = str(media_type).lower()
        if 'ssd' in mt_lower:
            spd_score += 2
            spd_notes.append(self.ui.c("✓ Тип носителя: SSD (быстрый)", 'ok'))
        elif 'hdd' in mt_lower:
            spd_score += 1
            spd_notes.append(self.ui.c("~ Тип носителя: HDD (механический)", 'warn'))
        elif 'removable' in mt_lower or 'unspecified' in mt_lower:
            spd_score += 1
            spd_notes.append(self.ui.c("~ Тип носителя: Съёмный (Flash)", 'dim'))
        else:
            spd_notes.append(self.ui.c(f"~ Тип носителя: {media_type}", 'dim'))

        # Ёмкость устройства
        if size_b >= 256 * 1024**3:
            spd_score += 2
            spd_notes.append(self.ui.c(f"✓ Ёмкость: {fmt_size(size_b)} (высокая)", 'ok'))
        elif size_b >= 32 * 1024**3:
            spd_score += 1
            spd_notes.append(self.ui.c(f"✓ Ёмкость: {fmt_size(size_b)} (хорошая)", 'ok'))
        elif size_b >= 4 * 1024**3:
            spd_score += 1
            spd_notes.append(self.ui.c(f"~ Ёмкость: {fmt_size(size_b)} (базовая)", 'warn'))
        else:
            spd_notes.append(self.ui.c(f"✗ Ёмкость: {fmt_size(size_b)} (менее 4 ГБ — ограниченная)", 'err'))

        # Таблица разделов
        if part_style == 'GPT':
            spd_score += 1
            spd_notes.append(self.ui.c(f"✓ Разметка: GPT ({part_count} разд.) — современный стандарт", 'ok'))
        elif part_style == 'MBR':
            spd_score += 1
            spd_notes.append(self.ui.c(f"~ Разметка: MBR ({part_count} разд.) — устаревший, но рабочий", 'warn'))
        else:
            spd_notes.append(self.ui.c(f"✗ Разметка: RAW ({part_count} разд.) — диск не инициализирован", 'err'))

        # Файловая система
        if fs_type:
            fs_up = fs_type.upper()
            if fs_up in ('NTFS', 'EXFAT', 'EXT4', 'APFS', 'REFS'):
                spd_score += 1
                spd_notes.append(self.ui.c(f"✓ Файловая система: {fs_type} (современная)", 'ok'))
            elif fs_up in ('FAT32', 'FAT16', 'FAT'):
                spd_notes.append(self.ui.c(f"~ Файловая система: {fs_type} (устаревшая, лимит 4 ГБ/файл)", 'warn'))
            else:
                spd_notes.append(self.ui.c(f"~ Файловая система: {fs_type}", 'dim'))
        else:
            spd_notes.append(self.ui.c("~ Файловая система: не определена", 'dim'))

        # Заполненность
        fill_pct = 0.0
        if size_b > 0 and used_b > 0:
            fill_pct = min(100.0, used_b * 100 / size_b)
            if fill_pct < 75:
                spd_notes.append(self.ui.c(f"✓ Заполненность: {fill_pct:.1f}% (свободно)", 'ok'))
            elif fill_pct < 90:
                spd_notes.append(self.ui.c(f"⚠ Заполненность: {fill_pct:.1f}% (плотная загрузка)", 'warn'))
            elif fill_pct < 98:
                spd_notes.append(self.ui.c(f"⚠ Заполненность: {fill_pct:.1f}% (критически мало места!)", 'warn'))
            else:
                spd_notes.append(self.ui.c(f"✗ Заполненность: {fill_pct:.1f}% (переполнен!)", 'err'))
        else:
            spd_notes.append(self.ui.c("~ Заполненность: данные недоступны", 'dim'))

        spd_bar = self.ui.progress_bar(spd_score * 10, 20)

        # ═══════════════════════════════════════════════════════
        # ИТОГОВЫЙ БАЛЛ (взвешенное среднее)
        # Надёжность × 0.40, Контроллер × 0.30, Скорость × 0.30
        # ═══════════════════════════════════════════════════════
        total_raw = round(rel_score * 0.40 + ctrl_score * 0.30 + spd_score * 0.30, 1)
        n_stars   = max(0, min(5, round(total_raw / 2)))
        stars     = self.ui.c('★' * n_stars, 'ok') + self.ui.c('☆' * (5 - n_stars), 'dim')

        if   total_raw >= 8.5: verdict = self.ui.c("ПРЕВОСХОДНОЕ СОСТОЯНИЕ", 'ok')
        elif total_raw >= 7.0: verdict = self.ui.c("ОТЛИЧНОЕ СОСТОЯНИЕ",     'ok')
        elif total_raw >= 5.5: verdict = self.ui.c("ХОРОШЕЕ СОСТОЯНИЕ",      'ok')
        elif total_raw >= 4.0: verdict = self.ui.c("УДОВЛЕТВОРИТЕЛЬНО",      'warn')
        elif total_raw >= 2.5: verdict = self.ui.c("ТРЕБУЕТ ВНИМАНИЯ",       'warn')
        else:                  verdict = self.ui.c("КРИТИЧЕСКОЕ СОСТОЯНИЕ",  'err')

        # ── Строки для отображения SMART ──
        if temp:
            tv = int(temp)
            tc = 'err' if tv > 55 else ('warn' if tv > 40 else 'ok')
            smart_temp_str = self.ui.c(f"{tv}°C", tc)
        else:
            smart_temp_str = self.ui.c('Нет данных', 'dim')

        health_col = 'ok' if h_lower == 'healthy' else ('warn' if h_lower == 'warning' else 'dim')
        health_str = self.ui.c(health, health_col)

        # Строки PowerOnHrs / Wear для секции SMART
        poh_str  = self.ui.c(f"{int(power_on_hrs)} ч.  ({int(power_on_hrs)//24} дней)", 'info') if power_on_hrs else self.ui.c("Н/Д", 'dim')
        wear_str = self.ui.c(f"{int(wear_val)}%", 'ok' if int(wear_val) <= 20 else ('warn' if int(wear_val) <= 60 else 'err')) if wear_val is not None else self.ui.c("Н/Д", 'dim')
        re_str   = self.ui.c(str(int(read_errors)), 'ok' if int(read_errors) == 0 else 'warn') if read_errors is not None else self.ui.c("Н/Д", 'dim')
        we_str   = self.ui.c(str(int(write_errors)), 'ok' if int(write_errors) == 0 else 'warn') if write_errors is not None else self.ui.c("Н/Д", 'dim')

        # ── Полоса заполненности ──
        if size_b > 0 and used_b > 0:
            fill_bar_str = self.ui.progress_bar(fill_pct, 22)
            fill_disp = f"{fill_bar_str} {fmt_size(used_b)} / {fmt_size(size_b)}"
        else:
            fill_disp = self.ui.c('Нет данных', 'dim')

        # ══════════════════════════════════════════════════════════
        # ОТРИСОВКА
        # ══════════════════════════════════════════════════════════
        W   = 62
        sep = self.ui.c('  ' + '─' * W, 'dim')

        def lbl(text): return self.ui.c(f"{text:<22}", 'dim')
        def row(label, value): print(f"  {self.ui.c('│', 'dim')} {lbl(label)}: {value}")
        def section(title):
            t = f"══ {title} "
            print(f"  {self.ui.c('╟' + t + '─' * max(1, W - len(t)), 'highlight')}")

        print(f"\n  {self.ui.c('╔══ АППАРАТНАЯ СВОДКА ' + '═' * (W - 19) + '╗', 'highlight')}")
        print(f"  {self.ui.c('║', 'highlight')}  "
              f"{self.ui.c('ДИСК:', 'dim')} {self.ui.c(d_num_str, 'warn')}  "
              f"{self.ui.c('│', 'dim')}  {stars}  "
              f"{self.ui.c(f'{total_raw:.1f}/10', 'info')}  {verdict}")
        print(sep)

        # ─── ИДЕНТИФИКАЦИЯ ─────
        section("ИДЕНТИФИКАЦИЯ")
        row("Имя устройства", self.ui.c(vendor, 'text'))
        row("Серийный номер", self.ui.c(sn, 'text'))
        row("Прошивка (REV)", self.ui.c(firmware, 'text'))
        row("Режим записи", ro_status)
        row("Физический размер", self.ui.c(f"{fmt_size(size_b)}  ({total_gb:.2f} ГБ)", 'info'))
        print(sep)

        # ─── INTERFACE ──────
        section("INTERFACE И НАКОПИТЕЛЬ")
        row("Шина данных", self.ui.c(bus_str, 'text'))
        row("Теор. скорость", self.ui.c(bus_speed, 'info'))
        row("Тип носителя", self.ui.c(media_type, 'text'))
        row("Таблица разделов", self.ui.c(f"{part_style}  ({part_count} разд.)", 'info'))
        row("Файловая система", self.ui.c(fs_type or 'Н/Д', 'info'))
        row("Занято / Объём", fill_disp)
        row("Статус диска", self.ui.c(op_status, health_col))
        print(sep)

        # ─── СЧЁТЧИКИ НАДЁЖНОСТИ ──────
        section("S.M.A.R.T И СЧЁТЧИКИ")
        row("Статус здоровья", health_str)
        row("Температура", smart_temp_str)
        row("Ошибки чтения", re_str)
        row("Ошибки записи", we_str)
        row("Износ NAND", wear_str)
        row("Наработка", poh_str)
        print(sep)

        # ─── КОНТРОЛЛЕР ───────
        section("КОНТРОЛЛЕР USB")
        row("VENDOR ID (VID)", f"{self.ui.c('0x' + vid, 'warn')}  {self.ui.c(v_db, 'ok')}")
        row("PRODUCT ID (PID)", f"{self.ui.c('0x' + pid, 'warn')}  {self.ui.c(p_db, 'ok')}")
        if pnp_id:
            row("PnP Device ID", self.ui.c(pnp_id[:55], 'dim'))
        print(sep)

        # ─── АНАЛИЗ КОНТРОЛЛЕРА ────
        section(f"АНАЛИЗ КОНТРОЛЛЕРА  [{ctrl_bar} {ctrl_score}/10]")
        for note in ctrl_notes:
            print(f"  {self.ui.c('│', 'dim')}   {note}")
        print(sep)

        # ─── АНАЛИЗ НАДЁЖНОСТИ ─────
        section(f"АНАЛИЗ НАДЁЖНОСТИ   [{rel_bar} {rel_score}/10]")
        for note in rel_notes:
            print(f"  {self.ui.c('│', 'dim')}   {note}")
        print(sep)

        # ─── АНАЛИЗ СКОРОСТИ ──────
        section(f"АНАЛИЗ СКОРОСТИ     [{spd_bar} {spd_score}/10]")
        for note in spd_notes:
            print(f"  {self.ui.c('│', 'dim')}   {note}")
        print(sep)

        # ─── ИТОГ ──────
        print(f"  {self.ui.c('╠══ ИТОГОВАЯ ОЦЕНКА ' + '═' * (W - 18) + '╣', 'highlight')}")
        total_bar = self.ui.progress_bar(total_raw * 10, 42)
        weight_info = self.ui.c("Надёжн.×40% + Контр.×30% + Скор.×30%", 'dim')
        print(f"  {self.ui.c('║', 'highlight')}  {total_bar}  {self.ui.c(f'{total_raw:.1f}/10', 'info')}  {stars}")
        print(f"  {self.ui.c('║', 'highlight')}  {verdict}  ({weight_info})")
        print(f"  {self.ui.c('╚' + '═' * W + '╝', 'highlight')}")


    @protective_shell
    def export_hw_report(self, hw: dict, v_db: str, p_db: str) -> str:
        """Экспорт красивого HTML отчета."""
        if getattr(sys, 'frozen', False):
            base_dir = Path(sys.executable).parent
        else:
            base_dir = Path(os.path.abspath(__file__)).parent

        sn = hw.get('sn', 'ND') or 'ND'
        import re
        sn_safe = re.sub(r'[^\\w]', '_', sn)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        out_path = base_dir / f"DD_REPORT_{sn_safe}_{ts}.html"

        try:
            from jinja2 import Template
        except ImportError:
            Template = None

        if Template:
            template_str = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>DeepDrive Hardware Report - {{ sn }}</title>
                <style>
                    body { font-family: "Courier New", Courier, monospace; background-color: #050508; color: #d2d2d2; padding: 20px; }
                    .container { max-width: 800px; margin: 0 auto; border: 1px solid #333; padding: 20px; box-shadow: 0 0 10px rgba(36, 228, 213, 0.2); }
                    h1 { color: #24e4d5; border-bottom: 1px solid #333; padding-bottom: 10px; }
                    h2 { color: #888; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #222; }
                    th { color: #24e4d5; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>DEEPDRIVE V2.3 - HARDWARE REPORT</h1>
                    <p><strong>Generated:</strong> {{ ts }}</p>
                    <p><strong>Device ID:</strong> PhysicalDrive{{ hw.get('d_num', 'N/A') }}</p>
                    <h2>Identification</h2>
                    <table>
                        <tr><th>OS Name</th><td>{{ hw.get('vendor', 'N/A') }}</td></tr>
                        <tr><th>Size</th><td>{{ hw.get('size', 0) }} Bytes</td></tr>
                        <tr><th>Bus</th><td>{{ hw.get('bus', 'N/A') }}</td></tr>
                        <tr><th>Serial Number</th><td style="color:#ffc800">{{ sn }}</td></tr>
                        <tr><th>Firmware</th><td>{{ hw.get('ver', 'N/A') }}</td></tr>
                    </table>
                    <h2>Controller Data</h2>
                    <table>
                        <tr><th>Vendor ID</th><td style="color:#50e678">{{ hw.get('vid','0000') }} - {{ v_db }}</td></tr>
                        <tr><th>Product ID</th><td style="color:#50e678">{{ hw.get('pid','0000') }} - {{ p_db }}</td></tr>
                        <tr><th>PNP ID</th><td>{{ hw.get('PNP', 'N/A') }}</td></tr>
                    </table>
                </div>
            </body>
            </html>
            """
            t = Template(template_str)
            html = t.render(hw=hw, v_db=v_db, p_db=p_db, sn=sn, ts=ts)
        else:
            # Fallback string formatting
            html = f"<html><body><h1>DeepDrive Report</h1><p>SN: {sn}</p><p>Vendor: {hw.get('vendor', 'N/A')}</p></body></html>"

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)

        self.logger.info(f"HTML Report exported: {out_path}")
        return str(out_path)

    def parse_mbr(self, d_num: int):
        """Детальный парсинг загрузочных секторов MBR и таблиц GPT."""
        path = f"\\\\.\\PhysicalDrive{d_num}"
        self.logger.info(f"Парсинг MBR/GPT для {path}")

        with open(path, 'rb') as disk_file:
            data = disk_file.read(512)

        if data[510:512] != b'\x55\xAA':
            print(self.ui.c("  [-] ОШИБКА: Недействительная сигнатура MBR (отсутствует 55 AA).", "err"))
            return

        partition_table = data[446:510]
        fs_types = {
            0x07: "NTFS/exFAT", 0x0B: "FAT32", 0x0C: "FAT32 (LBA)",
            0x83: "Linux ext", 0xEE: "GPT Защитный", 0x0F: "Extended LBA"
        }

        # Проверка на наличие GPT (тип раздела 0xEE)
        is_gpt = False
        for i in range(4):
            if partition_table[i*16 + 4] == 0xEE:
                is_gpt = True
                break

        if is_gpt:
            print(self.ui.c("\n  [+] Обнаружен GPT (GUID Partition Table). Чтение заголовка...", "ok"))

            with open(path, 'rb') as disk_file:
                disk_file.seek(512)
                gpt_hdr = disk_file.read(512)

            if gpt_hdr[:8] == b'EFI PART':
                ent_lba = struct.unpack("<Q", gpt_hdr[72:80])[0]
                num_ent = struct.unpack("<I", gpt_hdr[80:84])[0]
                ent_sz = struct.unpack("<I", gpt_hdr[84:88])[0]

                with open(path, 'rb') as disk_file:
                    disk_file.seek(ent_lba * 512)

                    for i in range(min(num_ent, 128)): # Читаем максимум 128 разделов
                        entry = disk_file.read(ent_sz)
                        if entry[:16] == b'\x00'*16:
                            continue # Пустой слот

                        start_lba = struct.unpack("<Q", entry[32:40])[0]
                        end_lba = struct.unpack("<Q", entry[40:48])[0]
                        name = entry[56:128].decode('utf-16le').rstrip('\x00')
                        size_mb = ((end_lba - start_lba + 1) * 512) / (1024 * 1024)

                        print(self.ui.c(f"  GPT РАЗДЕЛ {i+1}:", "highlight"))
                        print(f"    ├─ Имя        : {name or 'БЕЗ ИМЕНИ'}")
                        print(f"    ├─ Старт LBA  : {start_lba}")
                        print(f"    └─ Размер     : {size_mb:.2f} МБ\n")
        else:
            print(self.ui.c("\n  [+] MBR Сигнатура валидна. Парсинг классической таблицы:\n", "ok"))
            for i in range(4):
                entry = partition_table[i*16:(i+1)*16]
                part_type = entry[4]

                if part_type == 0:
                    continue # Пустой раздел

                status = "Активный/Boot" if entry[0] == 0x80 else "Неактивный"
                fs_desc = fs_types.get(part_type, f"Неизвестно (0x{part_type:02X})")

                lba_start = struct.unpack("<I", entry[8:12])[0]
                lba_size = struct.unpack("<I", entry[12:16])[0]
                size_mb = (lba_size * 512) / (1024 * 1024)

                print(self.ui.c(f"  MBR РАЗДЕЛ {i+1}:", "highlight"))
                print(f"    ├─ Статус     : {status}")
                print(f"    ├─ Тип ФС     : {fs_desc}")
                print(f"    ├─ Старт LBA  : {lba_start}")
                print(f"    └─ Размер     : {size_mb:.2f} МБ\n")

    @protective_shell
    def check_encryption(self, d_num: int, size: int):
        """Сканирует диск на предмет зашифрованных контейнеров через энтропию Шеннона."""
        path = f"\\\\.\\PhysicalDrive{d_num}"
        self.ui.slow_print("  [*] Расчет математической энтропии по случайной выборке...", "info")

        with open(path, 'rb') as f:
            # Прыгаем в середину диска (там обычно данные)
            f.seek(max(0, size // 2))
            sample = f.read(1024 * 1024 * 10) # Выборка 10 МБ

            counts = collections.Counter(sample)
            entropy = -sum((c/len(sample)) * math.log2(c/len(sample)) for c in counts.values() if c > 0)

            print(f"\n  │ Уровень энтропии: {self.ui.c(f'{entropy:.4f} / 8.0000', 'warn')}")

            if entropy > 7.99:
                print(self.ui.c("  │ ВЕРДИКТ: Данные зашифрованы (BitLocker, VeraCrypt) или это архив.", "err"))
            elif entropy < 2.0:
                print(self.ui.c("  │ ВЕРДИКТ: Пустая область или нули. Шифрование отсутствует.", "ok"))
            else:
                print(self.ui.c("  │ ВЕРДИКТ: Стандартные данные. Признаков крипто-контейнера нет.", "ok"))

    # --- ИНСТРУМЕНТЫ АДМИНИСТРИРОВАНИЯ (RUFUS) ---

    @protective_shell
    def partition_manager(self, d_num: int):
        """Обертка над Diskpart для создания новых разделов."""

        if HardwareManager.is_system_drive(d_num):
            return print(self.ui.c("  [-] ОШИБКА БЕЗОПАСНОСТИ: Попытка изменять системный диск Windows!", "err"))
        if self.write_block:
            return print(self.ui.c("  [-] ОТКЛОНЕНО: Включен программный Write-Blocker!", "err"))

        print("  1 - FAT32 (Совместимость)\n  2 - exFAT (Для больших файлов)\n  3 - NTFS (Для Windows)\n  0 - Отмена")
        choice = input(self.ui.c("\n  Выберите файловую систему >> ", "highlight"))

        fs_map = {"1": "fat32", "2": "exfat", "3": "ntfs"}
        if choice not in fs_map:
            return

        confirm = input(self.ui.c("  Введите 'FORMAT' для уничтожения текущих разделов >> ", "warn"))
        if confirm != "FORMAT":
            return

        target_fs = fs_map[choice]
        self.logger.info(f"Форматирование диска {d_num} в {target_fs}")
        self.ui.slow_print("  [*] Выполнение командного сценария Diskpart...", "info")

        diskpart_script = f"select disk {d_num}\nclean\ncreate partition primary\nformat fs={target_fs} quick\nassign\nexit\n"

        subprocess.run(["diskpart"], input=diskpart_script.encode('utf-8'), stdout=subprocess.DEVNULL)
        self.ui.slow_print("  [+] Раздел успешно создан, отформатирован и смонтирован.", "ok")

    def hardware_lock_worker(self, ctx: TaskContext, d_num: int, lock: bool, letter: str):
        """Асинхронная блокировка/разблокировка с проверкой аппаратного тумблера."""
        try:
            ctx.update(f"Применение защиты уровня ОС: {'ВКЛ' if lock else 'ВЫКЛ'}...")

            if not lock:
                dp_script = f"select disk {d_num}\nattributes disk clear readonly\nexit\n"
                subprocess.run(["diskpart"], input=dp_script.encode('utf-8'), stdout=subprocess.DEVNULL)
                reg_cmd = 'reg add "HKLM\\System\\CurrentControlSet\\Control\\StorageDevicePolicies" /v WriteProtect /t REG_DWORD /d 0 /f'
                subprocess.run(reg_cmd, shell=True, stdout=subprocess.DEVNULL)

            ps_cmd = f"Set-Disk -Number {d_num} -IsReadOnly {'$true' if lock else '$false'}"
            subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True)

            # --- ТЕСТ АППАРАТНОГО ТУМБЛЕРА (LOCK) ---
            if not lock and letter and letter[1] == ':':
                ctx.update("ОС разблокирована. Проверка физического доступа к флэш-памяти...")
                time.sleep(1)
                test_file = f"{letter[:2]}\\deepdrive_test_io.tmp"
                try:
                    with open(test_file, 'w') as f:
                        f.write("test_io")
                    os.remove(test_file)
                    ctx.result = "УСПЕХ! Программный блок снят, тумблер записи ОТКРЫТ."
                except PermissionError:
                    ctx.error = "ОШИБКА I/O: Атрибуты ОС сняты, но запись невозможна! Проверьте физический переключатель (Lock) на корпусе!"
                    return
                except Exception as e:
                    ctx.result = f"Атрибуты сняты, но тест ФС не удался: {e}"
            else:
                ctx.result = "Атрибуты применены успешно."
        except Exception as e:
            ctx.error = str(e)

    def power_cycle_worker(self, ctx: TaskContext, letter: str):
        """Перезагрузка USB порта через фоновый поток без фриза UI."""
        hw = HardwareManager.get_hw_info(letter)
        if hw.get("PNP"):
            ctx.update("Перезапуск концентратора USB (Disable/Enable)... Ждите.")
            ps = f"Disable-PnpDevice -InstanceId '{hw['PNP']}' -Confirm:$false; Start-Sleep -Seconds 2; Enable-PnpDevice -InstanceId '{hw['PNP']}' -Confirm:$false"
            subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True)
            ctx.result = "Питание порта сброшено. Устройство должно переподключиться."
        else:
            ctx.error = "Не удалось определить системный PNP ID для сброса."


    # --- ФОНОВЫЕ ВОРКЕРЫ (FORENSICS & RECOVERY) ---

    def carver_worker(self, ctx: TaskContext, letter: str):
        """Fast Carver - Поиск и извлечение файлов по их RAW-сигнатурам с Aho-Corasick."""
        import mmap
        try:
            import ahocorasick
            HAS_AHOCORASICK = True
        except ImportError:
            HAS_AHOCORASICK = False

        path = f"\\\\.\\{letter}"

        if getattr(sys, 'frozen', False):
            base_dir = Path(sys.executable).parent
        else:
            base_dir = Path(os.path.abspath(__file__)).parent

        out_dir = base_dir / f"Recovered_Files_{int(time.time())}"
        out_dir.mkdir(exist_ok=True)

        found_counts = {ext: 0 for _, _, ext in self.signatures}
        for ext in found_counts.keys():
            (out_dir / ext).mkdir(exist_ok=True)

        if HAS_AHOCORASICK:
            automaton = ahocorasick.Automaton()
            for i, (sig_start, sig_end, ext) in enumerate(self.signatures):
                automaton.add_word(sig_start, (i, sig_start, sig_end, ext))
            automaton.make_automaton()

        try:
            fd = os.open(path, os.O_RDONLY | os.O_BINARY)
            try:
                with mmap.mmap(fd, 0, access=mmap.ACCESS_READ) as mm:
                    total_size = mm.size()
                    if HAS_AHOCORASICK:
                        for end_idx, (idx, sig_start, sig_end, ext) in automaton.iter(mm):
                            if ctx.cancel: break
                            start_idx = end_idx - len(sig_start) + 1

                            file_end_idx = -1
                            if sig_end:
                                file_end_idx = mm.find(sig_end, start_idx + len(sig_start))
                            # Prevent MemoryError by enforcing a maximum file carve size
                            max_carve_size = 64 * 1024 * 1024
                            if file_end_idx != -1 and (file_end_idx - start_idx) > max_carve_size:
                                file_end_idx = -1

                            if file_end_idx == -1:
                                file_end_idx = min(start_idx + 1024*1024*2, total_size)
                            else:
                                file_end_idx += len(sig_end)

                            data = mm[start_idx:file_end_idx]

                            is_valid = True
                            if ext == "jpg" and (len(data) < 4 or data[-2:] != b'\xFF\xD9'):
                                is_valid = False

                            if is_valid and len(data) > min(len(sig_start)*2, 16):
                                found_counts[ext] += 1
                                file_path = out_dir / ext / f"recovered_{found_counts[ext]}.{ext}"
                                file_path.write_bytes(data)

                            if sum(found_counts.values()) % 10 == 0:
                                percent = (end_idx / total_size) * 100
                                bar = self.ui.progress_bar(percent)
                                ctx.update(f"Скан (Aho-Corasick): {percent:.1f}% {bar} Найдено: {sum(found_counts.values())} ф.")
                    else:
                        ctx.error = "Библиотека pyahocorasick не установлена."
                        return
            finally:
                os.close(fd)
            if not ctx.cancel:
                ctx.result = f"Восстановлено {sum(found_counts.values())} файлов. Папка: {out_dir.absolute()}"
        except Exception as e:
            self.logger.err(traceback.format_exc())
            ctx.error = str(e)

    def undelete_worker(self, ctx: TaskContext, letter: str):
        """Сложный сканер удаленных файлов в файловых системах NTFS, FAT32 и exFAT."""
        path = f"\\\\.\\{letter}"

        try:
            with open(path, "rb") as disk:
                # Читаем Volume Boot Record (VBR)
                vbr = disk.read(512)
                found_files = 0

                # Анализ NTFS
                if vbr[3:7] == b'NTFS':
                    bytes_per_sector = struct.unpack("<H", vbr[11:13])[0]
                    sectors_per_cluster = vbr[13]
                    mft_lcn = struct.unpack("<Q", vbr[48:56])[0]

                    disk.seek(mft_lcn * bytes_per_sector * sectors_per_cluster)

                    for _ in range(150000):
                        if ctx.cancel: break
                        record = bytearray(disk.read(1024))
                        if len(record) < 1024: break

                        if record[:4] == b"FILE":
                            usa_off = struct.unpack("<H", record[4:6])[0]
                            usa_cnt = struct.unpack("<H", record[6:8])[0]
                            if usa_off > 0 and usa_cnt == 3:
                                usn = record[usa_off:usa_off+2]
                                u1 = record[usa_off+2:usa_off+4]
                                u2 = record[usa_off+4:usa_off+6]
                                if record[510:512] == usn and record[1022:1024] == usn:
                                    record[510:512] = u1
                                    record[1022:1024] = u2

                            flags = struct.unpack("<H", record[22:24])[0]
                            if flags in (0x0000, 0x0002):
                                attr_pos = struct.unpack("<H", record[20:22])[0]
                                while attr_pos < 1000:
                                    attr_type = struct.unpack("<I", record[attr_pos:attr_pos+4])[0]
                                    if attr_type == 0xFFFFFFFF: break
                                    attr_len = struct.unpack("<I", record[attr_pos+4:attr_pos+8])[0]

                                    if attr_type == 0x30 and attr_len > 0 and attr_pos + attr_len <= 1024:
                                        if record[attr_pos+8] == 0:
                                            val_off = struct.unpack("<H", record[attr_pos+20:attr_pos+22])[0]
                                            name_len = record[attr_pos+val_off+64]
                                            name_bytes = record[attr_pos+val_off+66 : attr_pos+val_off+66 + name_len*2]
                                            try:
                                                filename = name_bytes.decode('utf-16le')
                                                self.logger.info(f"NTFS УДАЛЕНО: {filename}")
                                                found_files += 1
                                            except UnicodeDecodeError:
                                                pass
                                        break
                                    if attr_len == 0: break
                                    attr_pos += attr_len

                        if found_files % 10 == 0:
                            ctx.update(f"[NTFS] Анализ таблиц $MFT... Найдено: {found_files}")

                # Анализ FAT32
                elif vbr[82:90] == b'FAT32   ':
                    disk.seek(0)
                    prev_chunk = b''
                    for _ in range(10000):
                        if ctx.cancel: break
                        raw_data = disk.read(1024 * 1024 * 16)
                        if not raw_data: break

                        buffer = prev_chunk + raw_data
                        idx = 0
                        while True:
                            idx = buffer.find(b'\xE5', idx)
                            if idx == -1 or idx > len(buffer) - 32: break
                            attr = buffer[idx+11]
                            if attr in (0x10, 0x20):
                                if all(32 <= b <= 126 for b in buffer[idx+1:idx+8]):
                                    name = "_" + buffer[idx+1:idx+8].decode('ascii', errors='ignore').strip()
                                    ext_str = buffer[idx+8:idx+11].decode('ascii', errors='ignore').strip()
                                    if ext_str: name += "." + ext_str
                                    self.logger.info(f"FAT32 УДАЛЕНО: {name}")
                                    found_files += 1
                            idx += 32

                        prev_chunk = raw_data[-32:] if len(raw_data) >= 32 else raw_data
                        ctx.update(f"[FAT32] Поиск маркеров 0xE5... Найдено: {found_files}")

                # === НОВЫЙ БЛОК: Анализ exFAT ===
                elif vbr[3:11] == b'EXFAT   ':
                    bytes_per_sector = 1 << vbr[108] # Смещение 108: BytesPerSectorShift
                    cluster_heap_offset = struct.unpack("<I", vbr[88:92])[0]

                    # Прыгаем в область данных (Cluster Heap)
                    disk.seek(cluster_heap_offset * bytes_per_sector)
                    prev_chunk = b''

                    for _ in range(5000):
                        if ctx.cancel: break
                        raw_data = disk.read(1024 * 1024 * 16) # Читаем по 16 МБ
                        if not raw_data: break

                        buffer = prev_chunk + raw_data
                        idx = 0

                        # Двигаемся шагами по 32 байта (размер записи exFAT)
                        while idx <= len(buffer) - 32:
                            # 0x05 - Сигнатура удаленного файла в exFAT
                            if buffer[idx] == 0x05:
                                sec_count = buffer[idx + 1] # Сколько записей идет следом

                                if idx + (sec_count + 1) * 32 <= len(buffer):
                                    # Проверяем, что следующая запись - удаленный Stream Extension (0x40)
                                    if sec_count > 0 and buffer[idx + 32] == 0x40:
                                        filename_chars = []
                                        # Собираем куски имени из записей 0x41
                                        for i in range(2, sec_count + 1):
                                            entry_offset = idx + (i * 32)
                                            if buffer[entry_offset] == 0x41:
                                                name_part = buffer[entry_offset+2 : entry_offset+32]
                                                filename_chars.append(name_part)

                                        if filename_chars:
                                            full_name_bytes = b"".join(filename_chars)
                                            try:
                                                # Обрезаем нулевые байты конца строки
                                                filename = full_name_bytes.decode('utf-16le').split('\x00')[0]
                                                if filename and len(filename) > 1 and filename.isprintable():
                                                    self.logger.info(f"exFAT УДАЛЕНО: {filename}")
                                                    found_files += 1
                                            except UnicodeDecodeError:
                                                pass
                                    idx += (sec_count + 1) * 32
                                else:
                                    break # Хвост файла не влез в чанк, оставляем на следующий проход
                            else:
                                idx += 32

                        prev_chunk = buffer[idx:]
                        if found_files % 5 == 0:
                            ctx.update(f"[exFAT] Поиск каскадных записей 0x05... Найдено: {found_files}")
                else:
                    raise ValueError("Файловая система не поддерживается. Только NTFS / FAT32 / exFAT.")

            if not ctx.cancel:
                ctx.result = f"Анализ ФС завершен. Найдено {found_files} удаленных записей (см. Журнал)."

        except Exception as e:
            self.logger.err(traceback.format_exc())
            ctx.error = str(e)

    def yara_scan_worker(self, ctx: TaskContext, letter: str):
        """RAW-сканирование накопителя по YARA-правилам с автоматическим извлечением (Дампом) совпадений."""
        if yara is None:
            ctx.error = "Библиотека yara-python не установлена! (pip install yara-python)"
            return

        path = f"\\\\.\\{letter}"

        try:
            base_dir = Path(sys._MEIPASS)
        except Exception:
            base_dir = Path(os.path.abspath(__file__)).parent

        yara_file = base_dir / "rules.yar"
        if not yara_file.exists():
            ctx.error = f"Файл правил не найден: {yara_file.name}. Создайте его в папке с программой!"
            return

        ctx.update("Компиляция YARA-правил...")

        try:
            with open(yara_file, "r", encoding="utf-8") as f:
                yara_source = f.read()
            rules = yara.compile(source=yara_source)
        except yara.SyntaxError as e:
            ctx.error = f"Ошибка синтаксиса в rules.yar: {e}"
            return
        except Exception as e:
            ctx.error = f"Сбой инициализации YARA: {e}"
            return

        # Подготовка папки для сохранения "исходников" (дампов)
        out_dir = base_dir / f"YARA_Findings_{int(time.time())}"
        out_dir.mkdir(exist_ok=True)
        report_path = out_dir / "extracted_data.txt"

        chunk_size = 1024 * 1024 * 16 # Читаем по 16 МБ
        overlap = 1024 * 1024 * 2     # 2 МБ перекрытия
        scanned_bytes = 0
        matches_found = collections.defaultdict(int)

        try:
            with open(path, "rb") as disk, open(report_path, "w", encoding="utf-8") as report:
                report.write("=== DEEPDRIVE YARA EXTRACTION REPORT ===\n")
                report.write(f"Анализ диска: {path}\n")
                report.write(f"Дата сканирования: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                prev_chunk = b''
                while not ctx.cancel:
                    raw_data = disk.read(chunk_size)
                    if not raw_data:
                        break

                    buffer = prev_chunk + raw_data
                    buffer_start_offset = scanned_bytes - len(prev_chunk) if scanned_bytes > 0 else 0

                    matches = rules.match(data=buffer)
                    for match in matches:
                        matches_found[match.rule] += 1
                        self.logger.warn(f"[YARA DETECT] Правило '{match.rule}' сработало.")

                        for string_item in match.strings:

                            if isinstance(string_item, tuple):
                                # API < 4.3.0
                                extracted_instances = [(string_item[0], string_item[2])]
                            else:
                                # API >= 4.3.0
                                extracted_instances = [(inst.offset, inst.matched_data) for inst in string_item.instances]

                            for string_offset, string_data in extracted_instances:
                                abs_offset = buffer_start_offset + string_offset

                                decoded_str = string_data.decode('utf-8', errors='ignore').replace('\x00', '')

                                start_ctx = max(0, string_offset - 60)
                                end_ctx = min(len(buffer), string_offset + len(string_data) + 60)
                                context_bytes = buffer[start_ctx:end_ctx]

                                context_str = "".join(chr(b) if 32 <= b <= 126 or 1040 <= b <= 1103 else "." for b in context_bytes)
                                context_str = context_str.replace('\x00', '')

                                report.write(f"[!] УГРОЗА ПО ПРАВИЛУ: {match.rule}\n")
                                report.write(f"    ├─ Смещение диска : {abs_offset} (Сектор ~{abs_offset // 512})\n")
                                report.write(f"    ├─ Точное совпадение: {decoded_str}\n")
                                report.write(f"    └─ Контекст данных  : {context_str}\n")
                                report.write("-" * 80 + "\n")

                    scanned_bytes += len(raw_data)
                    prev_chunk = raw_data[-overlap:] if len(raw_data) >= overlap else raw_data

                    bar = self.ui.progress_bar( (scanned_bytes % 100) )
                    total_m = sum(matches_found.values())
                    ctx.update(f"YARA Скан: {fmt_size(scanned_bytes)} {bar} Найдено: {total_m} (Сохраняются в файл...) ")

            if not ctx.cancel:
                if matches_found:
                    res_str = ", ".join([f"{k}: {v}" for k, v in matches_found.items()])
                    ctx.result = f"Найдено: {res_str}. Отчет сохранен в папку {out_dir.name}!"
                else:
                    ctx.result = "Скан завершен. Совпадений по YARA-правилам не найдено."
                    report_path.unlink(missing_ok=True)
                    out_dir.rmdir()

        except Exception as e:
            self.logger.err(traceback.format_exc())
            ctx.error = str(e)


    def raw_image_dump_worker(self, ctx: TaskContext, d_num: int, total_size: int):
        """Создание полного посекторного дампа с вычислением хэша."""
        hasher = hashlib.sha256()
        path = f"\\\\.\\PhysicalDrive{d_num}"
        out_file = "deepdrive_raw_dump.img"
        written_bytes = 0

        try:
            with open(path, "rb") as source, open(out_file, "wb") as target:
                while not ctx.cancel:
                    chunk = source.read(1024 * 1024 * 16)
                    if not chunk:
                        break

                    target.write(chunk)
                    hasher.update(chunk)
                    written_bytes += len(chunk)

                    percent = (written_bytes / total_size) * 100
                    bar = self.ui.progress_bar(percent)
                    ctx.update(f"Дамп RAM: {percent:.1f}% {bar} {fmt_size(written_bytes)} / {fmt_size(total_size)}")

            if not ctx.cancel:
                hash_hex = hasher.hexdigest()
                self.logger.hash_log(out_file, hash_hex)
                ctx.result = f"Дамп сохранен. SHA-256: {hash_hex}"
        except Exception as e:
            ctx.error = str(e)


    def dod_wipe_worker(self, ctx: TaskContext, letter: str):
        """Исправленный DoD Wipe: затирание без системных ошибок."""
        hw = HardwareManager.get_hw_info(letter)
        d_num = hw['d_num']
        total_size = hw['size']

        if HardwareManager.is_system_drive(d_num):
            ctx.error = "ОШИБКА БЕЗОПАСНОСТИ: Попытка уничтожить системный диск Windows (C:)!"
            return
        if d_num is None or total_size == 0:
            ctx.error = "Не удалось определить параметры диска."
            return

        phys_path = f"\\\\.\\PhysicalDrive{d_num}"

        try:
            ctx.update("Подготовка шины...")
            subprocess.run(["diskpart"], input=f"select disk {d_num}\nclean\nexit\n".encode(), capture_output=True)
            time.sleep(1)

            passes = [(b'\x00', "Проход 1/3 (Нули)"), (b'\xFF', "Проход 2/3 (Единицы)"), (None, "Проход 3/3 (Рандом)")]

            fd = os.open(phys_path, os.O_RDWR | os.O_BINARY)
            try:
                for p_data, p_name in passes:
                    if ctx.cancel: break
                    written = 0
                    os.lseek(fd, 0, os.SEEK_SET) # Возврат в начало

                    while written < total_size and not ctx.cancel:
                        chunk_size = 1024 * 1024 * 4 # 4MB чанки
                        data = p_data * chunk_size if p_data else os.urandom(chunk_size)

                        if total_size - written < chunk_size:
                            data = data[:total_size - written]

                        os.write(fd, data)
                        written += len(data)

                        percent = (written / total_size) * 100
                        ctx.update(f"{p_name}: {percent:.1f}% {self.ui.progress_bar(percent)}")
            finally:
                os.close(fd)

            if not ctx.cancel:
                ctx.update("Восстановление структуры...")
                restore = f"select disk {d_num}\ncreate partition primary\nformat fs=ntfs quick\nassign letter={letter[0]}\nexit\n"
                subprocess.run(["diskpart"], input=restore.encode(), capture_output=True)
                ctx.result = "Уничтожение и переразметка завершены успешно."

        except Exception as e:
            ctx.error = f"Системный сбой: {e}"


    def speed_test_worker(self, ctx: TaskContext, letter: str):
        """Тестирование скорости линейного чтения с ремапом битых секторов."""
        path = f"\\\\.\\{letter}"
        chunk_size = 1024 * 1024 * 16
        read_bytes = 0
        bad_sectors = 0
        start_time = time.time()
        try:
            fd = os.open(path, os.O_RDWR | os.O_BINARY)
            try:
                while not ctx.cancel:
                    try:
                        os.lseek(fd, read_bytes, os.SEEK_SET)
                        chunk = os.read(fd, chunk_size)
                        if not chunk: break
                        read_bytes += len(chunk)
                        elapsed = time.time() - start_time
                        speed = (read_bytes / 1024 / 1024) / elapsed if elapsed > 0 else 0
                        spinner = ['|', '/', '-', '\\'][int(time.time() * 10) % 4]
                        speed_str = self.ui.color_speed(speed)
                        ctx.update(f"Тест Чтения {spinner}  Прочитано: {fmt_size(read_bytes)} | Скорость: {speed_str} | BAD: {bad_sectors}")
                    except OSError:
                        bad_sectors += 1
                        try:
                            os.lseek(fd, read_bytes, os.SEEK_SET)
                            os.write(fd, b'\x00' * chunk_size)
                        except OSError: pass
                        finally: read_bytes += chunk_size
            finally:
                os.close(fd)
            if not ctx.cancel: ctx.result = f"Завершено. Прочитано: {fmt_size(read_bytes)}. BAD-блоков: {bad_sectors}"
        except Exception as e:
            ctx.error = str(e)

    def iso_flasher_worker(self, ctx: TaskContext, letter: str, d_num: int, iso_path: Path):
        """Усовершенствованный RAW-флешер (DD-режим) с кольцевым буфером."""

        if HardwareManager.is_system_drive(d_num):
            ctx.error = "ОШИБКА БЕЗОПАСНОСТИ: Попытка записать ISO на системный диск Windows!"
            return
        import queue
        phys_path = f"\\\\.\\PhysicalDrive{d_num}"

        try:
            iso_size = iso_path.stat().st_size
            if iso_size == 0:
                raise ValueError("Выбранный ISO файл пуст или поврежден.")

            ctx.update("Подготовка накопителя: Очистка таблиц разделов (Diskpart)...")
            dp_script = f"select disk {d_num}\nclean\nexit\n"
            subprocess.run(["diskpart"], input=dp_script.encode('utf-8'), stdout=subprocess.DEVNULL)
            time.sleep(1.5)

            chunk_size = 1024 * 1024 * 8
            written_bytes = 0
            start_time = time.time()

            q = queue.Queue(maxsize=16)

            def reader():
                try:
                    with open(iso_path, "rb") as f:
                        while not ctx.cancel:
                            chunk = f.read(chunk_size)
                            if not chunk:
                                q.put(None)
                                break
                            q.put(chunk)
                except Exception:
                    q.put(None)

            def writer():
                nonlocal written_bytes
                try:
                    with open(phys_path, "wb") as f:
                        while not ctx.cancel:
                            chunk = q.get()
                            if chunk is None:
                                break
                            f.write(chunk)
                            written_bytes += len(chunk)
                            q.task_done()
                except Exception:
                    ctx.cancel = True

            r_thread = threading.Thread(target=reader, daemon=True)
            w_thread = threading.Thread(target=writer, daemon=True)
            r_thread.start()
            w_thread.start()

            while w_thread.is_alive():
                elapsed = time.time() - start_time
                if elapsed > 0.5:
                    speed_bps = written_bytes / elapsed
                    speed_mbps = speed_bps / (1024 * 1024)
                    bytes_left = iso_size - written_bytes
                    eta_seconds = bytes_left / speed_bps if speed_bps > 0 else 0
                    m, s = divmod(int(eta_seconds), 60)
                    eta_str = f"{m:02d}м {s:02d}с"
                    percent = (written_bytes / iso_size) * 100
                    bar = self.ui.progress_bar(percent, width=30)
                    spinner = ['|', '/', '-', '\\'][int(time.time() * 10) % 4]
                    ctx.update(f"Запись {spinner} {percent:.1f}% {bar} {speed_mbps:.1f} МБ/с | Ост: {eta_str}")
                time.sleep(0.1)

            r_thread.join()
            w_thread.join()

            if ctx.cancel:
                ctx.error = "Операция прервана пользователем или аппаратная ошибка."
                return

            ctx.update("Охлаждение буфера и верификация загрузочного сектора (LBA 0)...")
            time.sleep(1)

            with open(iso_path, "rb") as iso, open(phys_path, "rb") as disk:
                iso_lba0 = iso.read(512)
                disk_lba0 = disk.read(512)
                if iso_lba0 != disk_lba0:
                    raise IOError("КРИТИЧЕСКИЙ СБОЙ: Сигнатура загрузчика на диске не совпадает с ISO-образом.")

            ctx.update("Финализация: Переподключение подсистемы хранения...")
            subprocess.run(["powershell", "-NoProfile", "-Command", "Update-HostStorageCache"], capture_output=True)

            ctx.result = f"ISO '{iso_path.name}' успешно развернут ({fmt_size(iso_size)})."
        except PermissionError:
            ctx.error = "Отказано в доступе (0x05)."
        except Exception as e:
            ctx.error = f"Ошибка: {e}"

    def capacity_and_speed_test_worker(self, ctx: TaskContext, letter: str, d_num: int, total_size: int):
        """
        Комплексный тест для отбраковки флешек (Аналог H2testw).
        Проверяет реальный объем, ищет битые сектора, замеряет скорость и пишет лог в CSV.
        ВНИМАНИЕ: УНИЧТОЖАЕТ ВСЕ ДАННЫЕ НА ДИСКЕ!
        """
        if HardwareManager.is_system_drive(d_num):
            ctx.error = "ОШИБКА БЕЗОПАСНОСТИ: Попытка форматировать системный диск Windows (C:)!"
            return
        if self.write_block:
            ctx.error = "ОТКЛОНЕНО: Выключите Write-Blocker (Пункт 8) для проведения стресс-теста."
            return

        phys_path = f"\\\\.\\PhysicalDrive{d_num}"
        chunk_size = 1024 * 1024 * 8  # 8 МБ

        # Получаем данные о железе для CSV отчета
        hw_info = HardwareManager.get_hw_info(letter)

        write_speed_final = 0.0
        read_speed_final = 0.0
        corrupted_chunks = 0

        try:
            # --- ФАЗА 1: ПОДГОТОВКА ---
            ctx.update("Подготовка: Блокировка тома и снятие ФС...")
            with Win32DiskIO(phys_path, force_write_blocker=self.write_block) as io:
                if not io.lock_and_dismount():
                    raise OSError("Не удалось заблокировать том для эксклюзивного доступа.")

                with open(phys_path, "rb+") as disk:
                    # --- ФАЗА 2: ТЕСТ ЗАПИСИ ---
                    written_bytes = 0
                    start_time = time.time()
                    chunk_index = 0

                    while written_bytes < total_size and not ctx.cancel:
                        header = struct.pack("<8sQ", b"DEEPTEST", chunk_index)
                        data = header + (b'\xAA' * (chunk_size - 16))

                        if total_size - written_bytes < chunk_size:
                            data = data[:total_size - written_bytes]

                        disk.write(data)
                        written_bytes += len(data)
                        chunk_index += 1

                        elapsed = time.time() - start_time
                        if elapsed > 0.5:
                            speed_mb = (written_bytes / 1024 / 1024) / elapsed
                            percent = (written_bytes / total_size) * 100
                            bar = self.ui.progress_bar(percent, 20)
                            ctx.update(f"[ЗАПИСЬ] {percent:.1f}% {bar} Скорость: {speed_mb:.1f} МБ/с | Записано: {fmt_size(written_bytes)}")

                    if ctx.cancel:
                        ctx.error = "Тест прерван на этапе записи."
                        return

                    write_speed_final = (written_bytes / 1024 / 1024) / (time.time() - start_time)

                    # --- ФАЗА 3: ТЕСТ ЧТЕНИЯ И ВЕРИФИКАЦИИ ---
                    disk.seek(0)
                    read_bytes = 0
                    start_time = time.time()
                    expected_index = 0

                    while read_bytes < total_size and not ctx.cancel:
                        read_size = min(chunk_size, total_size - read_bytes)
                        chunk = disk.read(read_size)

                        if not chunk:
                            break

                        if len(chunk) >= 16:
                            sig, idx = struct.unpack("<8sQ", chunk[:16])
                            if sig != b"DEEPTEST" or idx != expected_index:
                                corrupted_chunks += 1

                        read_bytes += len(chunk)
                        expected_index += 1

                        elapsed = time.time() - start_time
                        if elapsed > 0.5:
                            speed_mb = (read_bytes / 1024 / 1024) / elapsed
                            percent = (read_bytes / total_size) * 100
                            bar = self.ui.progress_bar(percent, 20)
                            ctx.update(f"[ЧТЕНИЕ] {percent:.1f}% {bar} Скорость: {speed_mb:.1f} МБ/с | Ошибок: {corrupted_chunks}")

                    if ctx.cancel:
                        ctx.error = "Тест прерван на этапе чтения."
                        return

                    read_speed_final = (read_bytes / 1024 / 1024) / (time.time() - start_time)

            # --- ФАЗА 4: LOGGING, ФОРМАТИРОВАНИЕ И ИТОГИ ---

            self.logger.log_batch_result(hw_info, total_size, write_speed_final, read_speed_final, corrupted_chunks, chunk_size)

            ctx.update("Сброс тома: Быстрое форматирование в exFAT...")
            ps_cmd = f"Format-Volume -DriveLetter {letter[0]} -FileSystem exFAT -NewFileSystemLabel 'DEEP_TESTED' -Confirm:$false"
            subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd], capture_output=True)

            if corrupted_chunks > 0:
                lost_size = corrupted_chunks * chunk_size
                ctx.error = f"ФЕЙКОВЫЙ ОБЪЕМ ИЛИ БРАК! Повреждено {fmt_size(lost_size)}. Скорости: W:{write_speed_final:.1f} | R:{read_speed_final:.1f} МБ/с. Занесено в CSV."
            else:
                ctx.result = f"ОТЛИЧНО! Объем {fmt_size(total_size)} подтвержден. Скорости: W:{write_speed_final:.1f} | R:{read_speed_final:.1f} МБ/с. Занесено в CSV."

        except Exception as e:
            self.logger.err(traceback.format_exc())
            ctx.error = f"Сбой теста: {e}"


    def vhd_mount_worker(self, ctx: TaskContext, vhd_path: str):
        import ctypes
        from ctypes import wintypes
        try:
            virtdisk = ctypes.windll.virtdisk
            vst = type('VIRTUAL_STORAGE_TYPE', (ctypes.Structure,), {'_fields_': [("DeviceId", wintypes.ULONG), ("VendorId", ctypes.c_char * 16)]})()
            vst.DeviceId = 3 if str(vhd_path).lower().endswith('.vhdx') else 2
            vst.VendorId = (ctypes.c_char * 16)(*[0] * 16)
            open_params = type('OPEN_VIRTUAL_DISK_PARAMETERS_V1', (ctypes.Structure,), {'_fields_': [("Version", wintypes.ULONG), ("RWDepth", wintypes.ULONG)]})()
            open_params.Version = 1; open_params.RWDepth = 1
            handle = wintypes.HANDLE()
            res = virtdisk.OpenVirtualDisk(ctypes.byref(vst), ctypes.c_wchar_p(str(vhd_path)), 0x003F0000, 0, ctypes.byref(open_params), ctypes.byref(handle))
            if res == 0:
                attach_params = type('ATTACH_VIRTUAL_DISK_PARAMETERS_V1', (ctypes.Structure,), {'_fields_': [("Version", wintypes.ULONG)]})()
                attach_params.Version = 1
                res2 = virtdisk.AttachVirtualDisk(handle, None, 0x00000000, 0, ctypes.byref(attach_params), None)
                if res2 == 0: ctx.result = "VHD/VHDX успешно примонтирован."
                else: ctx.error = f"Ошибка AttachVirtualDisk: {res2}"
            else: ctx.error = f"Ошибка OpenVirtualDisk: {res}"
        except Exception as e: ctx.error = str(e)

    def ram_capture_worker(self, ctx: TaskContext):
        import urllib.request
        ctx.update("Скачивание WinPmem...")
        url = "https://github.com/Velocidex/WinPmem/releases/download/v3.0.rc3/winpmem_mini_x64_rc3.exe"
        exe_path = "winpmem.exe"
        dump_path = "physmem.raw"
        try:
            if not os.path.exists(exe_path): urllib.request.urlretrieve(url, exe_path)
            ctx.update("Создание дампа RAM (это может занять время)...")
            proc = subprocess.Popen([exe_path, dump_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            while proc.poll() is None and not ctx.cancel:
                line = proc.stdout.readline()
                if line: ctx.update(f"RAM Capture: {line.strip()[-50:]}")
                time.sleep(0.1)
            if ctx.cancel:
                proc.terminate()
                ctx.error = "Дамп отменен."
            elif proc.returncode == 0: ctx.result = f"Дамп сохранен в {dump_path}"
            else: ctx.error = f"Ошибка WinPmem: {proc.stderr.read()}"
        except Exception as e: ctx.error = str(e)

    def vss_mount_worker(self, ctx: TaskContext, letter: str):
        try:
            out = subprocess.check_output(["wmic", "shadowcopy", "get", "DeviceObject", "/format:csv"], text=True, stderr=subprocess.DEVNULL)
            paths = [line.split(',')[1].strip() for line in out.splitlines() if line.strip() and "DeviceObject" not in line]
            if not paths:
                ctx.error = "Теневые копии не найдены."
                return
            shadow_path = paths[-1]
            if not shadow_path.endswith("\\"): shadow_path += "\\"
            link_path = f"{letter[0]}Shadow\\"
            subprocess.check_call(["cmd", "/c", "mklink", "/d", link_path, shadow_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ctx.result = f"Теневая копия примонтирована в {link_path}"
        except Exception as e: ctx.error = str(e)


    def build_driver_worker(self, ctx: TaskContext):
        import base64
        # Dummy Base64 representation of a .sys driver file for DeepDriveIo
        # In a real environment, this would be a large base64 string of a compiled KMDF driver
        b64_sys = b'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAA='

        try:
            out_file = "DeepDriveIo.sys"
            with open(out_file, "wb") as f:
                f.write(base64.b64decode(b64_sys))

            ctx.update("Драйвер распакован. Регистрация службы...")

            try:
                subprocess.check_output(["sc", "query", "DeepDriveIo"], stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError:
                create_cmd = ["sc", "create", "DeepDriveIo", "binPath=", str(Path(out_file).absolute()), "type=", "kernel"]
                subprocess.check_call(create_cmd, stdout=subprocess.DEVNULL)

            ctx.update("Запуск драйвера уровня ядра...")
            start_cmd = ["sc", "start", "DeepDriveIo"]
            subprocess.check_call(start_cmd, stdout=subprocess.DEVNULL)

            ctx.result = f"БИНАРНЫЙ ДРАЙВЕР УСПЕШНО ЗАГРУЖЕН В ЯДРО!"
        except subprocess.CalledProcessError as e:
            ctx.error = "ОШИБКА ЗАГРУЗКИ. Убедитесь, что включен тестовый режим (bcdedit /set testsigning on)."
        except Exception as e:
            ctx.error = str(e)


    def registry_dump_worker(self, ctx: TaskContext):
        import shutil
        ctx.update("Теневое копирование реестра (SAM, SYSTEM, SOFTWARE)...")
        out_dir = Path("Registry_Dump")
        out_dir.mkdir(exist_ok=True)

        try:
            # Saving registry hives using reg.exe
            subprocess.check_call(["reg", "save", "HKLM\\SAM", str(out_dir / "SAM.hive"), "/y"], stdout=subprocess.DEVNULL)
            ctx.update("SAM сохранен. Копирование SYSTEM...")
            subprocess.check_call(["reg", "save", "HKLM\\SYSTEM", str(out_dir / "SYSTEM.hive"), "/y"], stdout=subprocess.DEVNULL)
            ctx.update("SYSTEM сохранен. Копирование SOFTWARE...")
            subprocess.check_call(["reg", "save", "HKLM\\SOFTWARE", str(out_dir / "SOFTWARE.hive"), "/y"], stdout=subprocess.DEVNULL)

            ctx.result = f"Ключевые ветви реестра скопированы в {out_dir.absolute()}"
        except subprocess.CalledProcessError:
            ctx.error = "Отказ в доступе. Требуются права Администратора."
        except Exception as e:
            ctx.error = str(e)

    def browser_history_worker(self, ctx: TaskContext):
        import shutil
        ctx.update("Поиск SQLite баз браузеров (Chrome, Edge)...")
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            ctx.error = "Не найден путь LOCALAPPDATA"
            return

        targets = {
            "Chrome_History": f"{local_app_data}\\Google\\Chrome\\User Data\\Default\\History",
            "Chrome_Cookies": f"{local_app_data}\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
            "Edge_History": f"{local_app_data}\\Microsoft\\Edge\\User Data\\Default\\History",
        }

        out_dir = Path("Browser_Forensics")
        out_dir.mkdir(exist_ok=True)
        found = 0

        try:
            for name, path in targets.items():
                if os.path.exists(path):
                    ctx.update(f"Копирование {name}...")
                    shutil.copy2(path, out_dir / f"{name}.sqlite")
                    found += 1
            if found > 0:
                ctx.result = f"Извлечено {found} баз данных браузеров."
            else:
                ctx.error = "БД браузеров не найдены или закрыты блокировками ОС."
        except Exception as e:
            ctx.error = str(e)


    def hidden_partition_worker(self, ctx: TaskContext, d_num: int):
        if HardwareManager.is_system_drive(d_num):
            ctx.error = "ОШИБКА БЕЗОПАСНОСТИ: Запрещено изменять разметку системного диска!"
            return

        ctx.update("Очистка таблиц и создание скрытого раздела (без буквы)...")
        # diskpart script: clean -> create partition -> format -> remove letter (or just don't assign one) -> set hidden attribute
        dp_script = f"select disk {d_num}\nclean\ncreate partition primary\nformat fs=exfat quick\nset id=12 hidden\nexit\n"

        try:
            res = subprocess.run(["diskpart"], input=dp_script.encode('utf-8'), capture_output=True)
            if res.returncode == 0:
                ctx.result = "Скрытый раздел успешно создан и отформатирован."
            else:
                ctx.error = f"Ошибка Diskpart: {res.stderr.decode('cp866', errors='ignore')}"
        except Exception as e:
            ctx.error = str(e)

    def hardware_reconstruction_worker(self, ctx: TaskContext, d_num: int):

        """
        ПРОТОКОЛ НИЗКОУРОВНЕВОЙ РЕКОНСТРУКЦИИ (L1 RECOVERY).
        Принудительное восстановление аппаратной доступности и разметки.
        """
        ctx.update(f"Инициализация шины для PhysicalDrive{d_num}...")

        commands = [
            "rescan",
            f"select disk {d_num}",
            "attributes disk clear readonly",
            "clean",
            "convert mbr",
            "create partition primary",
            "select partition 1",
            "active",
            "format fs=fat32 quick",
            "assign",
            "exit"
        ]

        script = "\n".join(commands)

        try:
            ctx.update("Выполнение реконструкции геометрии (Diskpart)...")
            process = subprocess.Popen(
                ["diskpart"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            stdout, stderr = process.communicate(input=script.encode('utf-8'), timeout=45)

            # Обновление системного кэша томов
            subprocess.run(["powershell", "Update-HostStorageCache"], capture_output=True)

            if process.returncode == 0:
                ctx.result = f"РЕКОНСТРУКЦИЯ ЗАВЕРШЕНА: Накопитель PhysicalDrive{d_num} возвращен в рабочее состояние."
            else:
                err = stderr.decode('cp866', errors='ignore')
                ctx.error = f"Отказ оборудования: {err}"

        except subprocess.TimeoutExpired:
            ctx.error = "ПРЕВЫШЕНО ВРЕМЯ ОЖИДАНИЯ: Контроллер диска не отвечает."
        except Exception as e:
            ctx.error = f"Критический сбой процесса: {e}"

# =====================================================================
# ГЛАВНЫЙ КОНТРОЛЛЕР ПРИЛОЖЕНИЯ
# =====================================================================

class App:
    def __init__(self):
        self.logger = ForensicLogger()
        self.ui = BiosTheme()
        self.db = LocalDB(self.ui, self.logger)
        self.engine = CoreEngine(self.ui, self.logger, self.db)
        self.tgt_letter = None
        self.is_readonly_mode = False
        self.op_state = "IDLE"

    def set_state_and_run(self, state: str, title: str, worker, danger: int, *args):
        """Обертка для безопасного запуска задач с автоматическим обновлением цели."""
        self.op_state = state
        self.ui.run_task(title, worker, danger, *args)

        if danger == 2:
            self.ui.slow_print("  [*] Финализация: Переподключение логических путей...", "info")
            time.sleep(2)
            self.tgt_letter = None
            self.op_state = "IDLE"
            return

        if self.tgt_letter:
            if not self.check_alive():
                self.tgt_letter = None

        self.op_state = "IDLE"

    def check_alive(self):
        """Мощный BSoD с 3-мя уровнями тяжести и авто-возвратом сессии."""
        if not self.tgt_letter:
            return True

        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        drive_idx = ord(self.tgt_letter[0].upper()) - 65

        if not (bitmask & (1 << drive_idx)):
            lost_drive = self.tgt_letter
            self.tgt_letter = None

            # --- Отрисовка BSoD ---
            sys.stdout.write("\033[44m\033[1;37m\033[2J\033[3J\033[H")
            sys.stdout.flush()

            print("\n  A problem has been detected and DEEPDRIVE has halted current operations")
            print("  to prevent data corruption in your forensic session.\n")

            if self.op_state == "CRITICAL":
                print("  STOP CODE: FATAL_DRIVE_CORRUPTION_IMMINENT")
                print(f"  [!!!] ОПАСНОЕ ИЗВЛЕЧЕНИЕ: Накопитель [{lost_drive}] выдернут во время записи/стирания!")
                print("  Таблицы разделов (MBR/GPT) или данные почти гарантированно уничтожены.")
                print("  Флешка с высокой вероятностью перейдет в RAW или зависнет.\n")
            elif self.op_state == "READ":
                print("  STOP CODE: UNSAFE_EXTRACTION_IO_ABORTED")
                print(f"  [!] НЕБЕЗОПАСНОЕ ИЗВЛЕЧЕНИЕ: Накопитель [{lost_drive}] отключен при чтении/анализе.")
                print("  Файловая система была смонтирована. Рекомендуется сканирование CHKDSK.\n")
            else:
                print("  STOP CODE: UNEXPECTED_HARDWARE_REMOVAL")
                print(f"  [*] Внезапное извлечение: Накопитель [{lost_drive}] отключен в режиме простоя.")
                print("  Риск аппаратной поломки минимален, но привычка плохая.\n")

            print("  ==========================================================================")
            print("  СИСТЕМНОЕ МЕНЮ ВОССТАНОВЛЕНИЯ (Нажмите цифру):")
            print("  [1] Игнорировать      -> Сбросить цель и вернуться в Главное меню")
            print("  [2] Проверка шины     -> Ожидание устройства на порту (Вставьте обратно)")
            print("  ==========================================================================\n")
            print("  [Авто-Детект] Вы можете просто вставить накопитель обратно в USB-порт...")

            scanning_mode = False

            while msvcrt.kbhit(): msvcrt.getch()

            while True:
                current_bitmask = ctypes.windll.kernel32.GetLogicalDrives()

                # Авто-определение (Флешка вернулась на место)
                if current_bitmask & (1 << drive_idx):
                    print(f"\n  [+] АППАРАТНОЕ ПРЕРЫВАНИЕ: Устройство {lost_drive} снова обнаружено!")
                    print("  [*] Инициализация контроллера и возврат в сессию...")
                    time.sleep(1.5)
                    self.tgt_letter = lost_drive
                    self.op_state = "IDLE"
                    self.ui.apply_bg()
                    return True

                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key == b'1':
                        self.op_state = "IDLE"
                        self.ui.apply_bg()
                        return False
                    elif key == b'2' and not scanning_mode:
                        scanning_mode = True
                        print("\n  [SCAN] Активный опрос шины запущен... Жду ответ от устройства.")

                time.sleep(0.1)

        return True

    def dev_mode_menu(self):
        """Режим Разработчика — глубокая настройка всего приложения."""
        cfg = self.ui.settings

        def _hdr(title):
            self.ui.header(f"DEV MODE  |  {title}", self.is_readonly_mode, self.engine.write_block)

        def _sep():
            return self.ui.c("  " + "-" * 68, "dim")

        def _edit_param(key, label, description, validator=None, choices=None):
            """Универсальный редактор параметра."""
            self.ui.clear()
            _hdr(label)
            current = cfg.get(key)
            default = cfg.DEFAULTS.get(key)
            print(f"  {self.ui.c('Параметр :', 'dim')}  {self.ui.c(key, 'highlight')}")
            print(f"  {self.ui.c('Описание :', 'dim')}  {description}")
            print(f"  {self.ui.c('Текущее  :', 'dim')}  {self.ui.c(str(current), 'info')}")
            print(f"  {self.ui.c('Заводское:', 'dim')}  {self.ui.c(str(default), 'dim')}")
            print(_sep())

            if isinstance(current, bool):
                opts = [
                    self.ui.c("[ON]  Включить", "ok"),
                    self.ui.c("[OFF] Выключить", "err"),
                    "Отмена",
                ]
                ch = self.ui.menu(label, opts, self.tgt_letter or "-",
                                  self.is_readonly_mode, self.engine.write_block)
                if ch == 0:   cfg.set(key, True);  cfg.save()
                elif ch == 1: cfg.set(key, False); cfg.save()
                return

            if choices:
                print(f"  {self.ui.c('Допустимые:', 'dim')} {self.ui.c(', '.join(choices), 'warn')}")
            print(f"  {self.ui.c('Введите значение (Enter = отмена):', 'highlight')}")
            raw = input(f"  {self.ui.c(key + ' >', 'info')} ").strip()
            if not raw:
                return
            try:
                if isinstance(current, int):   new_val = int(raw)
                elif isinstance(current, float): new_val = float(raw)
                else:                           new_val = raw
                if validator and not validator(new_val):
                    print(self.ui.c("  [!]  Недопустимое значение!", "err"))
                    time.sleep(1.2); return
                cfg.set(key, new_val); cfg.save()
                print(self.ui.c(f"  [OK] {key} = {new_val}", "ok"))
                time.sleep(0.6)
                # Мгновенно применяем цветовые изменения
                if key.startswith(('accent_', 'bg_', 'text_', 'dim_', 'warn_', 'err_', 'ok_')):
                    self.ui._rebuild_colors()
            except ValueError:
                print(self.ui.c(f"  [!]  Неверный формат для '{key}'.", "err"))
                time.sleep(1.2)

        # ---- Параметры по категориям ----------------------------------------
        CATEGORIES = [
            ("A. ЦВЕТА INTERFACEА", [
                ("accent_r",  "Акцент R",     "Красная составляющая акцентного цвета (0-255).",   lambda v: 0<=v<=255, None),
                ("accent_g",  "Акцент G",     "Зелёная составляющая акцентного цвета (0-255).",   lambda v: 0<=v<=255, None),
                ("accent_b",  "Акцент B",     "Синяя составляющая акцентного цвета (0-255).",     lambda v: 0<=v<=255, None),
                ("bg_r",      "Фон R",        "Красная составляющая фонового цвета (0-255).",     lambda v: 0<=v<=255, None),
                ("bg_g",      "Фон G",        "Зелёная составляющая фонового цвета (0-255).",     lambda v: 0<=v<=255, None),
                ("bg_b",      "Фон B",        "Синяя составляющая фонового цвета (0-255).",       lambda v: 0<=v<=255, None),
                ("text_r",    "Текст R",      "Красная составляющая цвета основного текста.",     lambda v: 0<=v<=255, None),
                ("text_g",    "Текст G",      "Зелёная составляющая цвета основного текста.",     lambda v: 0<=v<=255, None),
                ("text_b",    "Текст B",      "Синяя составляющая цвета основного текста.",       lambda v: 0<=v<=255, None),
                ("dim_r",     "Dim R",        "Красная составляющая приглушённого цвета.",        lambda v: 0<=v<=255, None),
                ("dim_g",     "Dim G",        "Зелёная составляющая приглушённого цвета.",        lambda v: 0<=v<=255, None),
                ("dim_b",     "Dim B",        "Синяя составляющая приглушённого цвета.",          lambda v: 0<=v<=255, None),
                ("warn_r",    "Warning R",    "Красная составляющая цвета предупреждений.",       lambda v: 0<=v<=255, None),
                ("warn_g",    "Warning G",    "Зелёная составляющая цвета предупреждений.",       lambda v: 0<=v<=255, None),
                ("warn_b",    "Warning B",    "Синяя составляющая цвета предупреждений.",         lambda v: 0<=v<=255, None),
                ("err_r",     "Error R",      "Красная составляющая цвета ошибок.",               lambda v: 0<=v<=255, None),
                ("err_g",     "Error G",      "Зелёная составляющая цвета ошибок.",               lambda v: 0<=v<=255, None),
                ("err_b",     "Error B",      "Синяя составляющая цвета ошибок.",                 lambda v: 0<=v<=255, None),
                ("ok_r",      "OK R",         "Красная составляющая цвета успеха.",               lambda v: 0<=v<=255, None),
                ("ok_g",      "OK G",         "Зелёная составляющая цвета успеха.",               lambda v: 0<=v<=255, None),
                ("ok_b",      "OK B",         "Синяя составляющая цвета успеха.",                 lambda v: 0<=v<=255, None),
            ]),
            ("B. ЭЛЕМЕНТЫ INTERFACEА", [
                ("slow_print_delay",   "Задержка печати",     "Скорость эффекта печатной машинки (сек, 0.0-0.05).", lambda v: 0.0<=v<=0.05, None),
                ("header_width",       "Ширина шапки",        "Ширина разделительной линии (40-120).",              lambda v: 40<=v<=120, None),
                ("header_char",        "Символ разделителя",  "Символ горизонтальной линии шапки.",                 lambda v: len(v)==1, ["-","=","*","#","_"]),
                ("header_title_prefix","Префикс заголовка",   "Строка перед названием раздела в шапке.",            None, [">>","[*]","//","##"]),
                ("progress_bar_width", "Ширина прогресса",    "Ширина progress bar в символах (10-60).",            lambda v: 10<=v<=60, None),
                ("progress_bar_fill",  "Символ заполнения",   "Символ заполненной части прогресс-бара.",            lambda v: len(v)==1, ["|","#","=","X","*"]),
                ("progress_bar_empty", "Символ пустоты",      "Символ пустой части прогресс-бара.",                 lambda v: len(v)==1, ["."," ","-","_"]),
                ("menu_pointer",       "Указатель курсора",   "Строка-указатель выбранного пункта меню.",           None, [">>","->","**","##","[ ]"]),
                ("menu_numbers",       "Нумерация пунктов",   "Показывать порядковый номер перед пунктом меню.",    None, None),
                ("compact_header",     "Компактная шапка",    "Убрать разделительные линии из шапки.",              None, None),
                ("show_write_blocker", "WB в шапке",          "Показывать статус Write-Blocker в шапке.",           None, None),
                ("blink_enabled",      "Мигание элементов",   "Разрешить мигание (ANSI blink) в интерфейсе.",       None, None),
            ]),
            ("C. PERFORMANCE", [
                ("chunk_size_kb",     "Блок I/O (КБ)",      "Размер чунка чтения/записи в тестах.",          lambda v: 64<=v<=4096, ["64","128","256","512","1024","2048","4096"]),
                ("read_buffer_mb",    "Буфер чтения (МБ)",  "Буфер RAW-дампа/карвера.",                      lambda v: 1<=v<=128,   ["1","4","8","16","32","64","128"]),
                ("carver_max_file_mb","Макс. файл карвера", "Максимальный размер восстанавливаемого файла.", lambda v: 1<=v<=2048,  ["16","32","64","128","256","512"]),
                ("speed_test_passes", "Проходы теста",      "Число итераций speed-теста для усреднения.",   lambda v: 1<=v<=20,    ["1","3","5","10","20"]),
                ("ps_timeout_sec",    "Таймаут PS (сек)",   "Макс. время ожидания PowerShell-запроса.",     lambda v: 5<=v<=120,   ["5","10","15","30","60"]),
                ("spinner_fps",       "Частота спиннера",   "Кадров/сек для анимации загрузки.",            lambda v: 1<=v<=30,    ["5","10","15","20","30"]),
                ("thread_pool_size",  "Потоков в пуле",     "Кол-во рабочих потоков (1-16).",               lambda v: 1<=v<=16,    ["1","2","4","8","16"]),
            ]),
            ("D. LOGGING", [
                ("log_max_count",   "Макс. лог-файлов",  "Кол-во хранимых сессионных логов (1-50).",  lambda v: 1<=v<=50,  ["3","5","10","25","50"]),
                ("log_tail_lines",  "Строк просмотра",   "Строк лога в просмотрщике сессии.",         lambda v: 10<=v<=500,["10","20","50","100","200"]),
                ("log_level",       "Уровень лога",      "Минимальный уровень записываемых событий.", None, ["DEBUG","INFO","WARNING","ERROR"]),
                ("log_timestamps",  "Метки времени",     "Показывать timestamp в просмотрщике.",      None, None),
                ("csv_delimiter",   "Разделитель CSV",   "Символ-разделитель для CSV-отчётов.",       lambda v: v in[";",",","\t"], [";",",","TAB(\\t)"]),
                ("log_to_file",     "Лог в файл",        "Записывать лог в файл на диске.",           None, None),
                ("log_to_console",  "Лог в консоль",     "Дублировать лог в консоль (verbose).",      None, None),
            ]),
            ("E. БЕЗОПАСНОСТЬ", [
                ("write_block_default", "WB по умолчанию",    "Write-Blocker вкл. автоматически при старте.",             None, None),
                ("confirm_wipe_phrase", "Фраза Wipe",         "Контрольная фраза для DoD Wipe (регистрозависимо).",        lambda v: len(v)>=2, None),
                ("confirm_burn_phrase", "Фраза Burn",         "Контрольная фраза для записи ISO.",                         lambda v: len(v)>=2, None),
                ("auto_hash_on_dump",   "Авто SHA256",        "Считать SHA256 после каждого RAW-дампа.",                   None, None),
                ("bsod_auto_return",    "Авто-выход BSoD",    "Вернуться в меню без нажатия клавиши после ошибки.",        None, None),
                ("bsod_scan_tip",       "Совет CHKDSK",       "Показать рекомендацию CHKDSK при небезопасном извлечении.", None, None),
                ("yara_rule_file",      "Файл YARA",          "Путь к файлу YARA-правил.",                                 lambda v: len(v)>=1, None),
                ("dod_passes",          "Проходов DoD",       "Число проходов затирания DoD 5220.22-M (1-7).",             lambda v: 1<=v<=7, ["1","3","7"]),
                ("require_admin_for_hex","Admin для HEX",     "Требовать Admin-права для HEX-просмотрщика.",               None, None),
                ("confirm_format",      "Подтверждение форм.","Запрашивать подтверждение перед форматированием.",          None, None),
                ("exit_confirm",        "Подтверждение выхода","Запрашивать подтверждение при выходе из программы.",      None, None),
            ]),
            ("F. ЭКСПЕРИМЕНТАЛЬНОЕ", [
                ("exp_hex_realtime",   "HEX: авто-обновление","HEX-просмотр: авто-обновление при смене сектора.",        None, None),
                ("exp_carver_deep",    "Carver: глубокий поиск","Carver: x4 медленнее, но находит больше фрагментов.",    None, None),
                ("exp_ps_raw_mode",    "PS: сырой режим",     "PowerShell: сырой вывод без JSON-парсинга.",               None, None),
                ("exp_force_mbr",      "Форсировать MBR",     "Анализировать GPT-диски как MBR (для экспериментов).",     None, None),
                ("exp_skip_signature", "Пропуск сигнатур",    "Не проверять сигнатуры файлов при карвинге.",              None, None),
                ("exp_unlocked_wipe",  "Wipe без WB-проверки","Разрешить Wipe без проверки Write-Blocker.",               None, None),
            ]),
            ("G. ОТЛАДКА", [
                ("dev_verbose_errors", "Полный traceback",   "Показывать traceback прямо в консоли.",                    None, None),
                ("dev_show_ps_output", "Сырой PS-вывод",     "Выводить raw-ответ PowerShell в консоль.",                 None, None),
                ("dev_disable_bsod",   "Откл. BSoD-экран",   "При ошибке диска — сразу в меню, без BSoD.",              None, None),
                ("dev_fake_admin",     "Симул. Admin-прав",  "Пропускать UAC-проверку (win32-операции всё равно сломаются).", None, None),
                ("dev_dry_run",        "Dry Run",            "Симулировать деструктивные операции без записи на диск.",  None, None),
                ("dev_perf_timings",   "Замеры времени",     "Показывать время каждой операции в консоли.",             None, None),
                ("dev_menu_debug",     "Debug меню",         "Показывать indices выбора и внутренние переменные меню.",  None, None),
                ("dev_skip_checks",    "Пропуск проверок",   "Пропускать все предварительные проверки системы.",        None, None),
            ]),
        ]

        # ---- Встроенные пресеты -----------------------------------------------
        BUILTIN_PRESETS = {
            "PERFORMANCE": {
                "chunk_size_kb": 1024, "read_buffer_mb": 16,
                "carver_max_file_mb": 256, "speed_test_passes": 1,
                "ps_timeout_sec": 10, "spinner_fps": 20,
                "slow_print_delay": 0.0, "thread_pool_size": 8,
            },
            "FORENSICS": {
                "chunk_size_kb": 512, "read_buffer_mb": 4,
                "carver_max_file_mb": 64, "speed_test_passes": 5,
                "auto_hash_on_dump": True, "dod_passes": 7,
                "write_block_default": True, "log_max_count": 10,
                "log_tail_lines": 100, "log_timestamps": True,
                "confirm_wipe_phrase": "FORENSIC_WIPE",
                "exp_carver_deep": True,
            },
            "DEBUG_ALL": {
                "dev_verbose_errors": True, "dev_show_ps_output": True,
                "dev_disable_bsod": True, "dev_dry_run": True,
                "dev_perf_timings": True, "dev_menu_debug": True,
                "dev_skip_checks": True, "slow_print_delay": 0.0,
                "spinner_fps": 30, "log_level": "DEBUG",
                "log_to_console": True,
            },
            "DARK_RED": {
                "accent_r": 220, "accent_g": 40, "accent_b": 40,
                "bg_r": 12, "bg_g": 4, "bg_b": 4,
                "text_r": 220, "text_g": 200, "text_b": 200,
                "ok_r": 80, "ok_g": 220, "ok_b": 80,
                "err_r": 255, "err_g": 50, "err_b": 50,
            },
            "HACKER_GREEN": {
                "accent_r": 0, "accent_g": 255, "accent_b": 70,
                "bg_r": 0, "bg_g": 10, "bg_b": 0,
                "text_r": 0, "text_g": 200, "text_b": 0,
                "dim_r": 0, "dim_g": 80, "dim_b": 0,
                "ok_r": 0, "ok_g": 255, "ok_b": 100,
                "err_r": 255, "err_g": 50, "err_b": 0,
            },
            "MIDNIGHT_BLUE": {
                "accent_r": 100, "accent_g": 180, "accent_b": 255,
                "bg_r": 4, "bg_g": 8, "bg_b": 20,
                "text_r": 180, "text_g": 200, "text_b": 230,
                "dim_r": 60, "dim_g": 80, "dim_b": 120,
                "ok_r": 80, "ok_g": 200, "ok_b": 255,
            },
        }

        # ---- Управление кастомными пресетами --------------------------------
        def _show_meta(meta: dict):
            """Красивый вывод метаданных пресета."""
            print(self.ui.c("  ╔══════════════════════════════════════════╗", "highlight"))
            print(self.ui.c(f"  ║  Пресет: {meta.get('name','?'):<33}║", "highlight"))
            print(self.ui.c(f"  ║  Тип   : {meta.get('type','?'):<33}║", "dim"))
            print(self.ui.c(f"  ║  Автор : {meta.get('author','?'):<33}║", "dim"))
            print(self.ui.c(f"  ║  Создан: {meta.get('created','?'):<33}║", "dim"))
            desc = meta.get('description', '')
            if desc:
                print(self.ui.c(f"  ║  Описание: {desc[:31]:<31}║", "text"))
            print(self.ui.c("  ╚══════════════════════════════════════════╝", "highlight"))

        def _custom_presets_menu():
            while True:
                _hdr("МЕНЕДЖЕР ПРЕСЕТОВ")
                custom_list = cfg.list_custom_presets()
                preset_dir = cfg.get_presets_dir()
                active_labels = cfg.menu_labels
                print(self.ui.c(f"  Директория: {preset_dir}", "dim"))
                print(self.ui.c(f"  Пресетов на диске: {len(custom_list)}", "info") +
                      (self.ui.c(f"   Overrides меню: {len(active_labels)}", "warn") if active_labels else ""))
                print(_sep())
                opts = [
                    "[+] Сохранить текущие → новый пресет",
                    "[~] Сохранить частичный (тема / производительность / ...)",
                    "[>] Загрузить пресет",
                    "[I] Просмотр информации о пресете",
                    "[X] Удалить пресет",
                    "[O] Открыть папку с пресетами",
                    "[R] Сброс к Factory Reset",
                    "[L] Редактор названий пунктов меню",
                    "[K] Редактор горячих клавиш (0-9 ⇒ пункт)",
                    "[-] Очистить кастомные названия меню",
                    "Назад",
                ]
                choice = self.ui.menu("МЕНЕДЖЕР ПРЕСЕТОВ", opts,
                                      self.tgt_letter or "-",
                                      self.is_readonly_mode, self.engine.write_block)
                if choice == -1 or choice == 10:
                    return

                if choice == 0:  # === СОХРАНИТЬ ПОЛНЫЙ ===
                    _hdr("НОВЫЙ ПРЕСЕТ")
                    name = input(f"  {self.ui.c('Название > ', 'info')}").strip()
                    if not name:
                        continue
                    desc = input(f"  {self.ui.c('Описание (Enter — пропустить) > ', 'dim')}").strip()
                    author_inp = input(f"  {self.ui.c('Автор (Enter = @Machinist) > ', 'dim')}").strip()
                    author = author_inp if author_inp else '@Machinist'
                    # Включить текущие кастомные названия меню?
                    preset_ml = {}
                    if cfg.menu_labels:
                        if input(self.ui.c(
                            "  Включить текущие кастомные названия пунктов меню? (Y/N) > ", "warn"
                        )).strip().upper() == 'Y':
                            preset_ml = cfg.menu_labels
                    cfg.save_custom_preset(name, preset_type='full', description=desc,
                                           author=author, menu_labels=preset_ml or None)
                    print(self.ui.c(f"  [OK] Пресет '{name}.json' сохранён (полный).", "ok"))
                    time.sleep(0.8)

                elif choice == 1:  # === ЧАСТИЧНЫЙ ПРЕСЕТ ===
                    _hdr("ЧАСТИЧНЫЙ ПРЕСЕТ")
                    type_opts = [
                        "ТЕМА — только цвета и стиль интерфейса",
                        "PERFORMANCE — I/O и буферы",
                        "БЕЗОПАСНОСТЬ — защиты, подтверждения, блокировки",
                        "ПОЛНЫЙ — все параметры",
                        "Назад",
                    ]
                    type_map = {0: 'theme', 1: 'performance', 2: 'security', 3: 'full'}
                    tc = self.ui.menu("ТИП ПРЕСЕТА", type_opts,
                                      self.tgt_letter or "-",
                                      self.is_readonly_mode, self.engine.write_block)
                    if tc == -1 or tc == 4:
                        continue
                    preset_type = type_map[tc]
                    name = input(f"  {self.ui.c('Название > ', 'info')}").strip()
                    if not name:
                        continue
                    desc = input(f"  {self.ui.c('Описание > ', 'dim')}").strip()

                    # Спрашиваем про menu_labels только для полного
                    preset_ml = {}
                    if preset_type == 'full' and cfg.menu_labels:
                        if input(self.ui.c(
                            "  Включить текущие overrides меню (_menu_labels) в пресет? (Y/N) > ", "warn")).strip().upper() == 'Y':
                            preset_ml = cfg.menu_labels

                    cfg.save_custom_preset(name, preset_type=preset_type,
                                           description=desc, menu_labels=preset_ml or None)
                    keys_count = len(cfg.build_preset_data(preset_type))
                    print(self.ui.c(f"  [OK] Пресет '{name}' ({preset_type}, {keys_count} ключей) сохранён.", "ok"))
                    time.sleep(0.9)

                elif choice == 2:  # === ЗАГРУЗИТЬ ===
                    if not custom_list:
                        print(self.ui.c("  [!] Нет сохранённых пресетов.", "warn"))
                        time.sleep(1)
                        continue
                    load_opts = []
                    for pname in custom_list:
                        m = cfg.get_preset_meta(pname)
                        lbl = f"{pname:<25} [{m.get('type','?'):<12}] @{m.get('author','?')}"
                        load_opts.append(lbl)
                    load_opts.append("Назад")
                    sel = self.ui.menu("ЗАГРУЗИТЬ ПРЕСЕТ", load_opts,
                                       self.tgt_letter or "-",
                                       self.is_readonly_mode, self.engine.write_block)
                    if sel == -1 or sel >= len(custom_list):
                        continue
                    pname = custom_list[sel]
                    # Показываем мета перед применением
                    meta_preview = cfg.get_preset_meta(pname)
                    self.ui.clear()
                    _hdr(f"ЗАГРУЗКА: {pname}")
                    _show_meta(meta_preview)
                    print()
                    confirm = input(self.ui.c("  Применить этот пресет? (Y, любая — отмена) > ", "highlight")).strip().upper()
                    if confirm != 'Y':
                        print(self.ui.c("  [--] Загрузка отменена.", "dim"))
                        time.sleep(0.8)
                        continue
                    ok, meta, warns = cfg.load_custom_preset(pname)
                    if ok:
                        self.ui._rebuild_colors()
                        print(self.ui.c(f"  [OK] Пресет '{pname}' применён!", "ok"))
                        if warns:
                            print(self.ui.c(f"  [!] Предупреждения ({len(warns)}):", "warn"))
                            for w in warns[:5]:
                                print(self.ui.c(f"       • {w}", "dim"))
                    else:
                        print(self.ui.c(f"  [X] Ошибка загрузки '{pname}'.", "err"))
                    time.sleep(1.0)

                elif choice == 3:  # === ИНФО О ПРЕСЕТЕ ===
                    if not custom_list:
                        print(self.ui.c("  [!] Нет пресетов.", "warn"))
                        time.sleep(1)
                        continue
                    info_opts = [f"{n}" for n in custom_list] + ["Назад"]
                    si = self.ui.menu("ИНФО О ПРЕСЕТЕ", info_opts,
                                      self.tgt_letter or "-",
                                      self.is_readonly_mode, self.engine.write_block)
                    if si == -1 or si >= len(custom_list):
                        continue
                    m = cfg.get_preset_meta(custom_list[si])
                    self.ui.clear()
                    _hdr(f"ИНФО: {custom_list[si]}")
                    _show_meta(m)
                    self.ui.pause()
                elif sub_choice == 2:
                    self.set_state_and_run("CRITICAL", "Экспорт драйвера", self.engine.build_driver_worker, 1)
                    self.ui.pause()

                elif choice == 4:  # === УДАЛИТЬ ===
                    if not custom_list:
                        print(self.ui.c("  [!] Нет пресетов для удаления.", "warn"))
                        time.sleep(1)
                        continue
                    del_opts = [f"[X] {n}" for n in custom_list] + ["Назад"]
                    di = self.ui.menu("УДАЛИТЬ ПРЕСЕТ", del_opts,
                                      self.tgt_letter or "-",
                                      self.is_readonly_mode, self.engine.write_block)
                    if di == -1 or di >= len(custom_list):
                        continue
                    pname = custom_list[di]
                    if input(self.ui.c(f"  Удалить '{pname}'? (Y/N) > ", "err")).strip().upper() == 'Y':
                        if cfg.delete_custom_preset(pname):
                            print(self.ui.c(f"  [OK] '{pname}' удалён.", "ok"))
                        else:
                            print(self.ui.c("  [X] Не удалось удалить файл.", "err"))
                    time.sleep(0.7)

                elif choice == 5:  # === ОТКРЫТЬ ПАПКУ ===
                    try:
                        os.startfile(str(preset_dir))
                    except Exception:
                        os.system(f'explorer "{preset_dir}"')

                elif choice == 6:  # === FACTORY RESET ===
                    self.ui.clear()
                    _hdr("СБРОС К ЗАВОДСКИМ НАСТРОЙКАМ")
                    print(self.ui.c("  Это действие сбросит ВСЕ настройки, включая:", "warn"))
                    print(self.ui.c("   • Цвета и тему", "dim"))
                    print(self.ui.c("   • Производительность и безопасность", "dim"))
                    print(self.ui.c("   • Overrides меню и горячие клавиши", "dim"))
                    print()
                    confirm = input(self.ui.c("  Введите 'RESET' для подтверждения > ", "err")).strip().upper()
                    if confirm == 'RESET':
                        cfg.reset_to_defaults()
                        self.ui._rebuild_colors()
                        print(self.ui.c("  [OK] Все параметры сброшены к заводским!", "ok"))
                    else:
                        print(self.ui.c("  [--] Отменено.", "dim"))
                    time.sleep(1.0)

                elif choice == 7:  # === РЕДАКТОР НАЗВАНИЙ МЕНЮ ===
                    # Список пунктов главного меню для отображения
                    _menu_items = [
                        "0: ВЫБОР УСТРОЙСТВА И ПИТАНИЕ",
                        "1: АНАЛИТИКА",
                        "2: БЕНЧМАРК",
                        "3: ОБРАЗЫ И КЛОНИРОВАНИЕ",
                        "4: РЕДАКТОР РАЗДЕЛОВ",
                        "5: ВОССТАНОВЛЕНИЕ ДАННЫХ",
                        "6: БЕЗОПАСНОСТЬ",
                        "7: WRITE-BLOCKER",
                        "8: HEX VIEWER",
                        "9: ЖУРНАЛ СЕССИИ",
                        "10: НАСТРОЙКИ",
                        "11: ВЫХОД",
                    ]
                    while True:
                        self.ui.clear()
                        _hdr("РЕДАКТОР НАЗВАНИЙ МЕНЮ")
                        print(self.ui.c("  Текущие overrides:", "highlight"))
                        if cfg.menu_labels:
                            for k, v in sorted(cfg.menu_labels.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 99):
                                orig = _menu_items[int(k)] if k.isdigit() and int(k) < len(_menu_items) else f"Пункт {k}"
                                print(self.ui.c(f"    [{k}]  {orig:<35}", "dim") +
                                      self.ui.c(f"  → {v}", "ok"))
                        else:
                            print(self.ui.c("    <нет кастомных названий>", "dim"))
                        print(_sep())
                        print(self.ui.c("  Пункты главного меню (индексы 0-11):", "info"))
                        for item in _menu_items:
                            idx_str = item.split(":")[0]
                            cur_lbl = cfg.menu_labels.get(idx_str, "")
                            mark = self.ui.c(f" → {cur_lbl}", "warn") if cur_lbl else ""
                            print(self.ui.c(f"    {item}{mark}", "text"))
                        print()
                        print(self.ui.c("  Введите номер пункта для переименования (Enter — выход):", "dim"))
                        idx_inp = input(f"  {self.ui.c('Индекс > ', 'info')}").strip()
                        if not idx_inp:
                            break
                        if not idx_inp.isdigit() or not (0 <= int(idx_inp) < len(_menu_items)):
                            print(self.ui.c("  [!] Неверный индекс.", "err"))
                            time.sleep(0.7)
                            continue
                        orig_name = _menu_items[int(idx_inp)].split(":", 1)[1].strip()
                        print(self.ui.c(f"  Текущее: {orig_name}", "dim"))
                        new_label = input(self.ui.c(
                            "  Новое название (Enter = сбросить) > ", "highlight"
                        )).strip()
                        if new_label:
                            cfg.menu_labels[idx_inp] = new_label
                        else:
                            cfg.menu_labels.pop(idx_inp, None)
                        cfg.save()
                        print(self.ui.c(f"  [OK] Пункт [{idx_inp}] обновлён.", "ok"))
                        time.sleep(0.5)

                elif choice == 8:  # === РЕДАКТОР ГОРЯЧИХ КЛАВИШ ===
                    # Хоткей формат: {"5": 10} = клавиша 5 запускает пункт 10
                    _hk_items = [
                        "0: ВЫБОР УСТРОЙСТВА",
                        "1: АНАЛИТИКА",
                        "2: БЕНЧМАРК",
                        "3: ОБРАЗЫ",
                        "4: РЕДАКТОР РАЗДЕЛОВ",
                        "5: ВОССТАНОВЛЕНИЕ",
                        "6: БЕЗОПАСНОСТЬ",
                        "7: WRITE-BLOCKER",
                        "8: HEX VIEWER",
                        "9: ЖУРНАЛ",
                        "10: НАСТРОЙКИ",
                        "11: ВЫХОД",
                    ]
                    while True:
                        self.ui.clear()
                        _hdr("РЕДАКТОР ГОРЯЧИХ КЛАВИШ")
                        print(self.ui.c("  Формат: клавиша 0-9 → индекс пункта (0-11)", "dim"))
                        print(self.ui.c("  Пример: '5' → '10' = нажатие 5 открывает НАСТРОЙКИ", "dim"))
                        print(_sep())
                        print(self.ui.c("  Текущие hotkeys:", "highlight"))
                        if cfg.hotkeys:
                            for k, v in sorted(cfg.hotkeys.items()):
                                tgt = _hk_items[int(v)] if str(v).isdigit() and int(v) < len(_hk_items) else f"Пункт {v}"
                                print(self.ui.c(f"    [{k}] → Пункт {v}: {tgt}", "ok"))
                        else:
                            print(self.ui.c("    <нет активных hotkeys>", "dim"))
                        print(_sep())
                        print(self.ui.c("  Доступные пункты:", "info"))
                        for it in _hk_items:
                            digit_key = it.split(":")[0]
                            cur_hk = [k for k, v in cfg.hotkeys.items() if str(v) == digit_key]
                            mark = self.ui.c(f"  [кл. {','.join(cur_hk)}]", "warn") if cur_hk else ""
                            print(self.ui.c(f"    {it}{mark}", "text"))
                        print()
                        key_inp = input(f"  {self.ui.c('Клавиша (0-9) для переназначения (Enter = выход) > ', 'info')}").strip()
                        if not key_inp:
                            break
                        if not key_inp.isdigit() or not (0 <= int(key_inp) <= 9):
                            print(self.ui.c("  [!] Нужна цифра 0-9.", "err"))
                            time.sleep(0.7); continue
                        tgt_inp = input(self.ui.c(
                            f"  Клавиша '{key_inp}' будет открывать пункт номер (0-11, Enter = сброс) > ", "highlight"
                        )).strip()
                        if not tgt_inp:
                            cfg.hotkeys.pop(key_inp, None)
                            print(self.ui.c(f"  [OK] Клавиша '{key_inp}' сброшена.", "ok"))
                        elif tgt_inp.isdigit() and 0 <= int(tgt_inp) < len(_hk_items):
                            cfg.hotkeys[key_inp] = int(tgt_inp)
                            print(self.ui.c(f"  [OK] [{key_inp}] → пункт {tgt_inp} ({_hk_items[int(tgt_inp)]})", "ok"))
                        else:
                            print(self.ui.c("  [!] Неверный номер пункта.", "err"))
                            time.sleep(0.7); continue
                        cfg.save()
                        time.sleep(0.5)

                elif choice == 9:  # === ОЧИСТИТЬ КАСТОМНЫЕ НАЗВАНИЯ ===
                    if not cfg.menu_labels and not cfg.hotkeys:
                        print(self.ui.c("  [--] Нет активных overrides.", "dim"))
                    else:
                        cfg.menu_labels = {}
                        cfg.hotkeys = {}
                        cfg.save()
                        print(self.ui.c(f"  [OK] Кастомные названия и hotkeys очищены.", "ok"))
                    time.sleep(0.8)


        # ---- Цветовой редактор RGB 3-в-1 ------------------------------------
        def _rgb_editor(r_key, g_key, b_key, label):
            """Интерактивный редактор R G B тремя значениями через пробел."""
            self.ui.clear()
            _hdr(f"RGB: {label}")
            r, g, b = cfg.get(r_key), cfg.get(g_key), cfg.get(b_key)
            preview = f"\033[38;2;{r};{g};{b}m{'#' * 10}\033[0m"
            print(f"  {self.ui.c('Текущий:', 'dim')}  R={self.ui.c(str(r),'info')} G={self.ui.c(str(g),'info')} B={self.ui.c(str(b),'info')}  {preview}")
            print(_sep())
            print(f"  {self.ui.c('Введите R G B через пробел (0-255), или Enter для отмены:', 'highlight')}")
            raw = input(f"  {self.ui.c(label + ' >', 'info')} ").strip()
            if not raw:
                return
            parts = raw.split()
            if len(parts) != 3:
                print(self.ui.c("  [!]  Нужно три числа через пробел.", "err"))
                time.sleep(1.0); return
            try:
                rv, gv, bv = (max(0, min(255, int(p))) for p in parts)
                cfg.set(r_key, rv); cfg.set(g_key, gv); cfg.set(b_key, bv)
                cfg.save()
                self.ui._rebuild_colors()
                print(self.ui.c(f"  [OK] {label} = {rv} {gv} {bv}", "ok"))
                time.sleep(0.6)
            except ValueError:
                print(self.ui.c("  [!]  Неверный формат.", "err"))
                time.sleep(1.0)

        # ---- Меню цветов (быстрый RGB редактор) -----------------------------
        def _colors_quick_menu():
            while True:
                _hdr("БЫСТРЫЙ РЕДАКТОР ЦВЕТОВ")
                # Показываем палитру
                for label, rk, gk, bk in [
                    ("ACCENT", "accent_r","accent_g","accent_b"),
                    ("FONE  ", "bg_r",    "bg_g",    "bg_b"),
                    ("TEXT  ", "text_r",  "text_g",  "text_b"),
                    ("DIM   ", "dim_r",   "dim_g",   "dim_b"),
                    ("WARN  ", "warn_r",  "warn_g",  "warn_b"),
                    ("ERR   ", "err_r",   "err_g",   "err_b"),
                    ("OK    ", "ok_r",    "ok_g",    "ok_b"),
                ]:
                    r,g,b = cfg.get(rk), cfg.get(gk), cfg.get(bk)
                    bar = f"\033[38;2;{r};{g};{b}m{'#' * 8}\033[0m"
                    print(f"    {self.ui.c(label,'dim')}  R={self.ui.c(str(r),'info'):>3}  G={self.ui.c(str(g),'info'):>3}  B={self.ui.c(str(b),'info'):>3}  {bar}")
                print(_sep())
                color_opts = [
                    "ACCENT — цвет акцента заголовков и выделения",
                    "ФОН    — цвет фона терминала",
                    "ТЕКСТ  — цвет основного текста",
                    "DIM    — приглушённый текст",
                    "WARN   — предупреждения",
                    "ERR    — ошибки",
                    "OK     — успех / зелёные элементы",
                    "Назад",
                ]
                c = self.ui.menu("РЕДАКТОР ЦВЕТОВ", color_opts,
                                 self.tgt_letter or "-",
                                 self.is_readonly_mode, self.engine.write_block)
                if c == -1 or c == 7: return
                pairs = [
                    ("accent_r","accent_g","accent_b","ACCENT"),
                    ("bg_r",    "bg_g",    "bg_b",    "FON"),
                    ("text_r",  "text_g",  "text_b",  "TEXT"),
                    ("dim_r",   "dim_g",   "dim_b",   "DIM"),
                    ("warn_r",  "warn_g",  "warn_b",  "WARN"),
                    ("err_r",   "err_g",   "err_b",   "ERR"),
                    ("ok_r",    "ok_g",    "ok_b",    "OK"),
                ]
                _rgb_editor(*pairs[c])

        # ---- Применить встроенный пресет ------------------------------------
        def _apply_builtin(name):
            preset = BUILTIN_PRESETS[name]
            for k, v in preset.items():
                cfg.set(k, v)
            cfg.save()
            self.ui._rebuild_colors()
            print(self.ui.c(f"  [OK] Пресет '{name}' применён.", "ok"))
            time.sleep(0.8)

        # ---- ГЛАВНЫЙ ЦИКЛ ---------------------------------------------------
        while True:
            _hdr("НАСТРОЙКИ РАЗРАБОТЧИКА И ТЕМЫ")

            # Мини-сводка флагов отладки
            flag_keys = ["dev_dry_run","dev_verbose_errors","dev_fake_admin",
                         "dev_disable_bsod","dev_perf_timings","dev_skip_checks",
                         "exp_carver_deep","exp_unlocked_wipe"]
            flags_line = ""
            for fk in flag_keys:
                short = fk.replace("dev_","D:").replace("exp_","E:").replace("_","")
                v = cfg.get(fk)
                icon = self.ui.c("[+]","ok") if v else self.ui.c("[-]","dim")
                flags_line += f"  {icon}{self.ui.c(short,'dim')}"
            print(flags_line)
            print(_sep())

            # Сводка ключевых параметров
            snap = [
                ("chunk_kb", "chunk_size_kb"), ("buf_mb", "read_buffer_mb"),
                ("pb_w", "progress_bar_width"), ("hdr_w", "header_width"),
                ("dod_p", "dod_passes"),        ("fps",   "spinner_fps"),
                ("ptr",   "menu_pointer"),      ("fill",  "progress_bar_fill"),
            ]
            row = ""
            for i, (short, key) in enumerate(snap):
                row += f"  {self.ui.c(short+'='+str(cfg.get(key)),'info')}"
                if (i+1) % 4 == 0:
                    print(row); row = ""
            if row: print(row)
            print(_sep())

            main_opts = [cat[0] for cat in CATEGORIES]
            main_opts += [
                "--- БЫСТРЫЙ РЕДАКТОР ЦВЕТОВ (RGB палитра) ---",
                "--- КАСТОМНЫЕ ПРЕСЕТЫ (сохранить / загрузить / удалить) ---",
                "Назад",
            ]

            choice = self.ui.menu("НАСТРОЙКИ И ТЕМЫ", main_opts,
                                  self.tgt_letter or "-",
                                  self.is_readonly_mode, self.engine.write_block)

            n_cats = len(CATEGORIES)
            if choice == -1 or choice == len(main_opts) - 1:
                return

            elif choice < n_cats:
                # Категория параметров
                cat_name, params = CATEGORIES[choice]
                while True:
                    _hdr(cat_name)
                    print(_sep())
                    param_opts = []
                    for key, label, desc, *_ in params:
                        cur = cfg.get(key)
                        if isinstance(cur, bool):
                            vs = self.ui.c("[ON] ","ok") if cur else self.ui.c("[OFF]","dim")
                        else:
                            vs = self.ui.c(str(cur), "info")
                        param_opts.append(f"{label:<30} {vs}")
                    param_opts.append("Назад")

                    pc = self.ui.menu(cat_name, param_opts,
                                      self.tgt_letter or "-",
                                      self.is_readonly_mode, self.engine.write_block)
                    if pc == -1 or pc == len(params):
                        break
                    if pc < len(params):
                        key, label, description, validator, choices = params[pc]
                        _edit_param(key, label, description, validator, choices)

            elif choice == n_cats:      _colors_quick_menu()
            elif choice == n_cats + 1:  _custom_presets_menu()
            elif choice == n_cats + 2:  _apply_builtin("PERFORMANCE")
            elif choice == n_cats + 3:  _apply_builtin("FORENSICS")
            elif choice == n_cats + 4:  _apply_builtin("DEBUG_ALL")
            elif choice == n_cats + 5:  _apply_builtin("DARK_RED")
            elif choice == n_cats + 6:  _apply_builtin("HACKER_GREEN")
            elif choice == n_cats + 7:  _apply_builtin("MIDNIGHT_BLUE")
            elif choice == n_cats + 8:
                cfg.reset_to_defaults()
                self.ui._rebuild_colors()
                print(self.ui.c("  [OK] Все параметры сброшены к заводским!", "ok"))
                time.sleep(0.8)



    def _exit_sequence(self):
        """Анимированный выход из программы с эффектом распада данных."""
        try:
            ts = os.get_terminal_size()
            w, h = ts.columns, ts.lines
        except Exception:
            w, h = 80, 24

        sys.stdout.write("\033[?25l") # Скрыть курсор

        # Эффект распада (Data Dissolve / Noise)
        chars = "01010101ABCDEF#!@$%^&*"
        matrix_colors = ["dim", "highlight", "text"]

        frames = 35
        for f in range(frames):
            # В каждом кадре "повреждаем" случайные участки экрана
            for _ in range(w * 2): # Плотность шума
                rx = random.randint(1, w)
                ry = random.randint(1, h)
                char = random.choice(chars)
                color = random.choice(matrix_colors)
                # Рисуем "шум" в случайной позиции
                sys.stdout.write(f"\033[{ry};{rx}H" + self.ui.c(char, color))

            if f == frames // 2:
                # В середине анимации выводим финальное сообщение
                msg = "── SESSION TERMINATED ──"
                pos_y = h // 2
                pos_x = (w - len(msg)) // 2
                sys.stdout.write(f"\033[{pos_y};{pos_x}H\033[1;5m" + self.ui.c(msg, "err") + "\033[0m")

            sys.stdout.flush()
            time.sleep(0.03)

        # Финальный занавес
        sys.stdout.write("\033[0m\033[2J\033[3J\033[H")
        sys.stdout.write("\033[?25h") # Показать курсор
        sys.stdout.flush()
        sys.exit(0)

    def run(self):
        self.ui.apply_bg()
        # Создаём Factory Reset пресет при первом запуске если не существует
        self.ui.settings.ensure_factory_reset_preset()

        # ── V2.2: Кинематографичный Intro с параллельной загрузкой ───────────
        self.ui.clear()

        logo_final = fr"""
   ____                  ____       _
  / __ \___  ___  ____  / __ \_____(_)   _____
 / / / / _ \/ _ \/ __ \/ / / / ___/ / | / / _ \
/ /_/ /  __/  __/ /_/ / /_/ / /  / /| |/ /  __/
\_____/\___/\___/ .___/_____/_/  /_/ |___/\___(_)
              /_/
"""
        try:
            ts = os.get_terminal_size()
            term_width, term_height = ts.columns, ts.lines
        except Exception:
            term_width, term_height = 80, 24

        lines = logo_final.strip("\n").split("\n")
        max_logo_w = max(len(l) for l in lines)
        start_y = term_height // 4

        # Контекст для фоновой загрузки
        load_ctx = TaskContext()
        load_thread = threading.Thread(target=self.db.fetch_and_load, args=(load_ctx,), daemon=True)
        load_thread.start()

        # Сетка для "сборки" логотипа
        grid = []
        for y, line in enumerate(lines):
            for x, char in enumerate(line):
                if char != " ":
                    padding = (term_width - max_logo_w) // 2
                    target_x = padding + x
                    target_y = start_y + y
                    grid.append({
                        "char": char,
                        "tx": target_x,
                        "ty": target_y,
                        "curr": random.choice(".:*=+"),
                        "done": False
                    })
                    # V2.2: Отрисовка "призрачного" контура для узнаваемости
                    sys.stdout.write(f"\033[{target_y};{target_x}H" + self.ui.c(char, "dim"))

        sys.stdout.flush()
        time.sleep(0.5) # Пауза перед началом "сборки"

        # Анимация "Вихрь": символы летят на свои места
        frames = 80 # Удвоили длительность
        for f in range(frames):
            sys.stdout.write("\033[?25l") # Hide cursor

            # Статус внизу
            status = load_ctx.get_status()
            status_line = f"Инициализация: {status}"
            sys.stdout.write(f"\033[{term_height-2};0H" + self.ui.c(status_line.center(term_width), "dim"))

            # Прогресс сборки (нелинейный)
            progress = (f / frames) ** 1.5

            for item in grid:
                if item["done"]:
                    continue

                # Вероятность закрепиться в этом кадре
                if random.random() < progress * 1.2:
                    item["curr"] = item["char"]
                    item["done"] = True
                    color = "highlight"
                else:
                    item["curr"] = random.choice("!@#$%^&*()_+-=[]{}|;:,.<>?/\\")
                    color = "highlight" # Или "dim" для большего контраста при сборке

                # Печать символа
                sys.stdout.write(f"\033[{item['ty']};{item['tx']}H" + self.ui.c(item["curr"], color))

            sys.stdout.flush()
            # Чуть ускоряем кадры к концу для динамики
            wait = 0.057 - (f / frames) * 0.03
            time.sleep(max(0.02, wait))

        # Финальная отрисовка основного логотипа
        for y, line in enumerate(lines):
            padding = (term_width - max_logo_w) // 2
            sys.stdout.write(f"\033[{start_y + y};{padding}H" + self.ui.c(line, "highlight"))

        # Плавное появление @Machinist
        time.sleep(0.5)
        author = "@Machinist | V2.3 RELEASED".center(term_width)
        # Эффект появления подписи (простой)
        sys.stdout.write(f"\033[{start_y + len(lines) + 1};0H" + self.ui.c(author, "dim"))
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()

        # Ожидание загрузки если нужно
        while load_thread.is_alive():
            status = load_ctx.get_status()
            sys.stdout.write(f"\033[{term_height-2};0H" + self.ui.c(f"Завершение: {status}".center(term_width), "dim"))
            sys.stdout.flush()
            time.sleep(0.1)

        time.sleep(0.8)
        sys.stdout.write(f"\033[{term_height-1};0H" + self.ui.c("Нажмите любую клавишу для входа...".center(term_width), "highlight"))
        sys.stdout.flush()
        msvcrt.getch()

        # ── ПЕРЕХОД К ПРАВАМ ДОСТУПА ─────────────────────────────────────────
        self.ui.clear()
        if not is_admin() and os.name == 'nt':
            options = ["Запросить права Администратора", "Продолжить в режиме [ТОЛЬКО ЧТЕНИЕ]"]
            choice = self.ui.menu("ОШИБКА ПРАВ ДОСТУПА", options, None, True, False)

            if choice == 0:
                if request_admin(): sys.exit(0)

            self.is_readonly_mode = True
            self.logger.warn("Программа запущена в ограниченном режиме.")
        # ─────────────────────────────────────────────────────────────

        categories = [
            "1. ВЫБОР УСТРОЙСТВА И ПИТАНИЕ",
            "2. АНАЛИТИКА",
            "3. БЕНЧМАРК",
            "4. ОБРАЗЫ И КЛОНИРОВАНИЕ",
            "5. РЕДАКТОР РАЗДЕЛОВ (Форматирование)",
            "6. ВОССТАНОВЛЕНИЕ ДАННЫХ",
            "7. БЕЗОПАСНОСТЬ",
            "8. ПРОГРАММНЫЙ БЛОКИРАТОР ЗАПИСИ (Write-Blocker)",
            "9. RAW HEX VIEWER (Просмотр секторов)",
            "10. ЖУРНАЛ СЕССИИ",
            "11. НАСТРОЙКИ",
            "0. ВЫХОД ИЗ СИСТЕМЫ"
        ]


        # Главный цикл
        while True:
            if not self.check_alive():
                continue

            wb_state = "[ВКЛЮЧЕН]" if self.engine.write_block else "[ВЫКЛЮЧЕН]"
            categories[7] = f"8. ПРОГРАММНЫЙ БЛОКИРАТОР ЗАПИСИ: {wb_state}"

            # Применяем overrides названий пунктов из загруженного пресета
            labels = self.ui.settings.menu_labels
            if labels:
                for idx_str, new_label in labels.items():
                    try:
                        idx = int(idx_str)
                        if 0 <= idx < len(categories):
                            categories[idx] = new_label
                    except (ValueError, IndexError):
                        pass

            main_choice = self.ui.menu("ГЛАВНОЕ МЕНЮ", categories, self.tgt_letter, self.is_readonly_mode, self.engine.write_block)

            # Защита от запуска аналитики без выбранного диска
            if main_choice in [1, 2, 3, 4, 5, 6, 7, 8] and not self.tgt_letter:
                print(self.ui.c("\n  ⚠  Накопитель не выбран. Перейдите в пункт 1.", "warn"))
                self.ui.pause()
                continue

            # 1. ВЫБОР УСТРОЙСТВА
            if main_choice == 0:
                self.ui.clear()
                self.ui.header("ВЫБОР ЦЕЛЕВОГО УСТРОЙСТВА", self.is_readonly_mode, self.engine.write_block)

                drives = []
                def fetch_task():
                    nonlocal drives
                    drives = HardwareManager.get_combined_usb_drives()

                t = threading.Thread(target=fetch_task)
                t.start()
                spinner = ['|', '/', '-', '\\']
                idx = 0
                while t.is_alive():
                    sys.stdout.write(f"\r  {self.ui.c('[*] Выполняется опрос шины USB, пожалуйста, ждите...', 'warn')} {spinner[idx % 4]} ")
                    sys.stdout.flush()
                    idx += 1
                    time.sleep(0.1)

                print(self.ui.c("\r  [+] Опрос контроллеров завершен.                                       \n", "ok"))

                options = [d['display'] for d in drives]
                options.append("Сброс питания порта (USB Power Cycle)")
                options.append("Назад")

                sub_choice = self.ui.menu("ВЫБОР ЦЕЛЕВОГО УСТРОЙСТВА", options, self.tgt_letter, self.is_readonly_mode, self.engine.write_block)

                if 0 <= sub_choice < len(drives):
                    selected = drives[sub_choice]
                    self.tgt_letter = f"{selected['letter']}:" if selected['letter'] else f"Disk #{selected['num']}"
                    self.logger.info(f"Выбрано устройство: {self.tgt_letter}")

                elif sub_choice == len(drives) and self.tgt_letter:
                    self.set_state_and_run("CRITICAL", "USB Power Cycle", self.engine.power_cycle_worker, 2, self.tgt_letter)
                    self.ui.pause()

           # 2. АНАЛИТИКА
            elif main_choice == 1:
                options = ["Аппаратная сводка", "Парсер MBR/GPT", "Скан Энтропии (Крипто-Анализ)", "YARA-Скан (Поиск по правилам)", "Назад"]
                sub_choice = self.ui.menu("АНАЛИТИКА", options, self.tgt_letter, self.is_readonly_mode, self.engine.write_block)
                hw_base = HardwareManager.get_hw_info(self.tgt_letter) # Базовый инфо для доступа к d_num

                if sub_choice == 0:
                    self.ui.clear()
                    self.ui.header("АППАРАТНАЯ СВОДКА", self.is_readonly_mode, self.engine.write_block)

                    hw = {}
                    def fetch_hw():
                        nonlocal hw
                        hw = HardwareManager.get_hw_info(self.tgt_letter)

                    # Запускаем фоновый поток и крутим спиннер
                    t = threading.Thread(target=fetch_hw)
                    t.start()
                    spinner = ['|', '/', '-', '\\']
                    idx = 0
                    while t.is_alive():
                        sys.stdout.write(f"\r  {self.ui.c('[*] Чтение аппаратуры и анализ шины USB...', 'info')} {spinner[idx % 4]} ")
                        sys.stdout.flush()
                        idx += 1
                        time.sleep(0.1)

                    sys.stdout.write("\r" + " " * 75 + "\r")
                    sys.stdout.flush()

                    v_db, p_db = self.db.resolve(hw.get('vid', '0000'), hw.get('pid', '0000'))

                    if p_db == "НЕИЗВЕСТНЫЙ КОНТРОЛЛЕР" and hw.get('vendor') not in ['Unknown', 'Unknown Device', 'Неизвестное устройство']:
                        p_db = f"{hw.get('vendor')} (Универсальный контроллер)"

                    self.engine.show_info(hw, v_db, p_db)
                    print()
                    # V2.2: экспорт сводки в файл
                    if input(self.ui.c("  Сохранить сводку в TXT-файл? (Y / любая клавиша) >> ", "dim")).strip().lower() == 'y':
                        saved = self.engine.export_hw_report(hw, v_db, p_db)
                        if saved:
                            print(self.ui.c(f"  ✓  Сохранено: {saved}", "ok"))
                    self.ui.pause()

                elif sub_choice == 1 and hw_base['d_num'] is not None:
                    self.engine.parse_mbr(hw_base['d_num'])
                    self.ui.pause()
                elif sub_choice == 2 and hw_base['d_num'] is not None:
                    self.engine.check_encryption(hw_base['d_num'], hw_base['size'])
                    self.ui.pause()
                elif sub_choice == 3:
                    self.set_state_and_run("READ", "YARA Scanner", self.engine.yara_scan_worker, 1, self.tgt_letter)
                    self.ui.pause()

            elif main_choice == 2:
                if self.is_readonly_mode:
                    continue
                options = [
                    "БЫСТРЫЙ ТЕСТ: Только скорость чтения",
                    "ГЛУБОКИЙ ТЕСТ: Проверка на фейковый объем (Запись + Чтение + Верификация)",
                    "Назад"
                ]
                sub_choice = self.ui.menu("ОТБРАКОВКА И БЕНЧМАРКИ", options, self.tgt_letter, self.is_readonly_mode, self.engine.write_block)
                hw = HardwareManager.get_hw_info(self.tgt_letter)

                if sub_choice == 0:
                    self.set_state_and_run("READ", "Speed Test", self.engine.speed_test_worker, 1, self.tgt_letter)
                    self.ui.pause()
                elif sub_choice == 1 and hw['d_num'] is not None:
                    print(self.ui.c(f"\n  [ВНИМАНИЕ] Этот тест УНИЧТОЖИТ все данные на {self.tgt_letter}", "err"))
                    print(self.ui.c("  Тест запишет данные на все доступные сектора для проверки контроллера.", "warn"))
                    if input(self.ui.c("  Начать тестирование? (Y/N) >> ", "highlight")).strip().lower() == 'y':
                        self.set_state_and_run("CRITICAL", "Стресс-тест контроллера", self.engine.capacity_and_speed_test_worker, 2, self.tgt_letter, hw['d_num'], hw['size'])
                    self.ui.pause()

            # 4. КЛОНИРОВАНИЕ
            elif main_choice == 3:
                if self.is_readonly_mode:
                    continue

                options = ["Снять RAW дамп памяти (С хэшированием SHA256)", "Запись загрузочного ISO-образа", "Собрать C++ драйвер", "Назад"]
                sub_choice = self.ui.menu("ОБРАЗЫ И КЛОНИРОВАНИЕ", options, self.tgt_letter, self.is_readonly_mode, self.engine.write_block)
                hw = HardwareManager.get_hw_info(self.tgt_letter)

                if sub_choice == 0 and hw['d_num'] is not None:
                    print(self.ui.c(f"\n  Требуется места: {fmt_size(hw['size'])}", "warn"))
                    if input(self.ui.c("  Начать клонирование? (Y/N) >> ", "highlight")).strip().lower() == 'y':
                        self.set_state_and_run("READ", "Клонирование RAW", self.engine.raw_image_dump_worker, 1, hw['d_num'], hw['size'])
                    self.ui.pause()
                elif sub_choice == 2:
                    self.set_state_and_run("CRITICAL", "Сборка драйвера (Base64 .sys)", self.engine.build_driver_worker, 1)
                    self.ui.pause()

                elif sub_choice == 1 and hw['d_num'] is not None:
                    if self.engine.write_block:
                        print(self.ui.c("  [-] ОТКЛОНЕНО: Включен программный Write-Blocker!", "err"))
                    else:
                        isos = list(Path('.').glob('*.iso'))
                        if not isos:
                            print(self.ui.c("\n  [-] ISO файлы не найдены в папке программы.", "err"))
                        else:
                            print("")
                            for i, iso in enumerate(isos):
                                print(f"    [{i}] {iso.name} ({fmt_size(iso.stat().st_size)})")

                            sel = input(self.ui.c("\n  Выберите номер ISO >> ", "highlight"))
                            if sel.isdigit() and 0 <= int(sel) < len(isos):
                                if input(self.ui.c("  Введите 'BURN' для записи (Уничтожит данные!) >> ", "warn")) == "BURN":
                                    self.set_state_and_run("CRITICAL", f"Запись {isos[int(sel)].name}", self.engine.iso_flasher_worker, 2, self.tgt_letter, hw['d_num'], isos[int(sel)])
                    self.ui.pause()

            # 5. РЕДАКТОР РАЗДЕЛОВ
            elif main_choice == 4:
                if self.is_readonly_mode:
                    continue
                sub_choice = self.ui.menu("РЕДАКТОР РАЗДЕЛОВ", ["Форматирование тома (FAT32/exFAT/NTFS)", "Создать СКРЫТЫЙ раздел", "Назад"], self.tgt_letter, self.is_readonly_mode, self.engine.write_block)
                hw = HardwareManager.get_hw_info(self.tgt_letter)
                if sub_choice == 0 and hw['d_num'] is not None:
                    self.engine.partition_manager(hw['d_num'])
                    self.ui.pause()
                elif sub_choice == 1 and hw['d_num'] is not None:
                    print(self.ui.c("\n  [ВНИМАНИЕ] Все данные на диске будут стерты.", "warn"))
                    if input(self.ui.c("  Создать скрытый раздел? (Y/N) >> ", "highlight")).strip().lower() == 'y':
                        self.set_state_and_run("CRITICAL", "Создание скрытого раздела", self.engine.hidden_partition_worker, 2, hw['d_num'])
                    self.ui.pause()

           # 6. ВОССТАНОВЛЕНИЕ
            elif main_choice == 5:
                options = [
                    "Smart Carver (Сигнатурный поиск RAW)",
                    "Undelete Protocol (Восстановление MFT/FAT)",
                    "Дамп реестра (SAM, SYSTEM, SOFTWARE)",
                    "Извлечение баз данных браузеров",
                    "Монтирование VHD/VHDX",
                    "Live RAM Capture",
                    "Монтирование теневой копии (VSS)",
                    "РЕКОНСТРУКЦИЯ (L1 Hardware Recovery)",
                    "Назад"
                ]
                sub_choice = self.ui.menu("МОДУЛЬ ВОССТАНОВЛЕНИЯ", options, self.tgt_letter, self.is_readonly_mode, self.engine.write_block)

                # Извлекаем номер диска из tgt_letter (хоть из "F:", хоть из "Disk #1")
                hw = HardwareManager.get_hw_info(self.tgt_letter)

                if sub_choice == 0:
                    self.set_state_and_run("READ", "Smart Carver", self.engine.carver_worker, 1, self.tgt_letter)
                    self.ui.pause()
                elif sub_choice == 1:
                    self.set_state_and_run("READ", "ФС Сканер", self.engine.undelete_worker, 1, self.tgt_letter)
                    self.ui.pause()
                elif sub_choice == 2:
                    self.set_state_and_run("READ", "Дамп реестра", self.engine.registry_dump_worker, 1)
                    self.ui.pause()
                elif sub_choice == 3:
                    self.set_state_and_run("READ", "Сбор БД браузеров", self.engine.browser_history_worker, 1)
                    self.ui.pause()
                elif sub_choice == 4:
                    vhd_path = input(self.ui.c("\n  Путь к VHD/VHDX файлу >> ", "info")).strip()
                    if vhd_path: self.set_state_and_run("CRITICAL", "Монтирование VHD", self.engine.vhd_mount_worker, 2, vhd_path)
                    self.ui.pause()
                elif sub_choice == 5:
                    self.set_state_and_run("READ", "RAM Capture", self.engine.ram_capture_worker, 1)
                    self.ui.pause()
                elif sub_choice == 6:
                    if self.tgt_letter: self.set_state_and_run("READ", "VSS Mount", self.engine.vss_mount_worker, 1, self.tgt_letter)
                    self.ui.pause()
                elif sub_choice == 7 and hw['d_num'] is not None:
                    print(self.ui.c("\n  [ВНИМАНИЕ] ЗАПУСК ПРОТОКОЛА АППАРАТНОЙ РЕКОНСТРУКЦИИ.", "warn"))
                    print("  Все текущие данные и таблицы разделов будут перезаписаны.")
                    if input(self.ui.c("  Подтвердить запуск? (Y/N) >> ", "highlight")).strip().lower() == 'y':
                        self.set_state_and_run("CRITICAL", "Hardware Recovery", self.engine.hardware_reconstruction_worker, 2, hw['d_num'])
                    self.ui.pause()


            # 7. БЕЗОПАСНОСТЬ
            elif main_choice == 6:
                if self.is_readonly_mode:
                    continue
                options = ["Включить аппаратную защиту (Read-Only LOCK)", "Снять аппаратную защиту (UNLOCK)", "DoD 5220.22-M Wipe (Гарантированное уничтожение)", "Назад"]
                sub_choice = self.ui.menu("БЕЗОПАСНОСТЬ И УНИЧТОЖЕНИЕ", options, self.tgt_letter, self.is_readonly_mode, self.engine.write_block)
                hw = HardwareManager.get_hw_info(self.tgt_letter)

                if sub_choice == 0 and hw['d_num'] is not None:
                    self.set_state_and_run("CRITICAL", "Установка защиты", self.engine.hardware_lock_worker, 2, hw['d_num'], True, self.tgt_letter)
                    self.ui.pause()
                elif sub_choice == 1 and hw['d_num'] is not None:
                    self.set_state_and_run("CRITICAL", "Снятие защиты", self.engine.hardware_lock_worker, 2, hw['d_num'], False, self.tgt_letter)
                    self.ui.pause()
                elif sub_choice == 2:
                    if self.engine.write_block:
                        print(self.ui.c("  [-] ОТКЛОНЕНО: Включен Write-Blocker!", "err"))
                    elif input(self.ui.c("  ВНИМАНИЕ! Введите 'DOD' для уничтожения >> ", "err")).strip().upper() == "DOD":
                        self.set_state_and_run("CRITICAL", "DoD Wipe", self.engine.dod_wipe_worker, 2, self.tgt_letter)
                    self.ui.pause()

            # 8. WRITE-BLOCKER
            elif main_choice == 7:
                self.ui.clear()
                self.ui.header("ПРОГРАММНЫЙ WRITE-BLOCKER", self.is_readonly_mode, self.engine.write_block)
                if self.engine.write_block:
                    print(self.ui.c("  [!] ЗАЩИТА СЕЙЧАС ВКЛЮЧЕНА. Диск защищен от программной записи.", "ok"))
                    if input(self.ui.c("  Отключить защиту? (Впишите 'UNLOCK') >> ", "highlight")) == 'UNLOCK':
                        self.engine.write_block = False
                        self.logger.warn("Write-Blocker ОТКЛЮЧЕН пользователем.")
                else:
                    self.engine.write_block = True
                    self.logger.info("Write-Blocker ВКЛЮЧЕН пользователем.")

            # 9. RAW HEX VIEWER
            elif main_choice == 8:
                hw = HardwareManager.get_hw_info(self.tgt_letter)
                if not hw or hw['d_num'] is None:
                    continue
                path = f"\\\\.\\PhysicalDrive{hw['d_num']}"
                if self.ui.settings.get('require_admin_for_hex') and not is_admin():
                    print(self.ui.c("\n  [-] ОШИБКА: Для RAW-чтения нужны права Администратора.", "err"))
                    self.ui.pause()
                    continue
                viewer = HexViewer(self.ui, path, hw['size'])
                viewer.view()

            # 10. ЖУРНАЛ СЕССИИ
            elif main_choice == 9:
                self.ui.clear()
                self.ui.header(f"ЖУРНАЛ ОТЛАДКИ (Файл: {self.logger.log_file.name})", self.is_readonly_mode, self.engine.write_block)
                count = self.ui.settings.get('log_tail_lines', 20)
                lines = self.logger.read_logs_tail(count)

                print(self.ui.c(f"  --- Последние {count} записей ---", "dim"))
                for line in lines:
                    if " - [ERROR]" in line:
                        print(f"  {self.ui.c(line, 'err')}")
                    elif " - [WARNING]" in line:
                        print(f"  {self.ui.c(line, 'warn')}")
                    else:
                        print(f"  {self.ui.c(line, 'text')}")

                self.ui.pause()

            # 11. НАСТРОЙКИ (Ex-DEV MODE)
            elif main_choice == 10:
                self.dev_mode_menu()

            # Выход
            elif main_choice == 11 or main_choice == -1:
                self.logger.info("Штатное завершение работы программы.")
                self._exit_sequence()



if __name__ == "__main__":
    if os.name == 'nt':
        try:
            App().run()
        except KeyboardInterrupt:
            sys.stdout.write("\033[0m\033[2J\033[3J\033[H")
            sys.exit(0)