# -*- coding: utf-8 -*-
"""
DeepDrive V2.2 — Builder
Собирает единый EXE через PyInstaller.
Автодетект всех необходимых ресурсов.
"""

import os
import sys
import subprocess
import shutil
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from pathlib import Path

# ─────────────────────────────────────────────
#  Авто-поиск ресурсов рядом со скриптом
# ─────────────────────────────────────────────
HERE = Path(__file__).resolve().parent

def _find(name: str, exts=()) -> str:
    """Ищет файл рядом со скриптом. Возвращает путь строкой или ''."""
    for ext in (exts or ('',)):
        p = HERE / (name + ext)
        if p.exists():
            return str(p)
    return ''


# ─────────────────────────────────────────────
#  Главный класс Builder
# ─────────────────────────────────────────────
class DeepDriveBuilder:
    APP_TITLE   = "DeepDrive Builder  V2.2"
    WIN_SIZE    = "760x720"
    BG_DARK     = "#0a0a0f"
    BG_DARKER   = "#060609"
    FG_ACCENT   = "#24e4d5"
    FG_OK       = "#50e678"
    FG_ERR      = "#ff3c3c"
    FG_WARN     = "#ffc800"
    FG_DIM      = "#555577"
    FONT_MONO   = ("Consolas", 9)
    FONT_LABEL  = ("Segoe UI", 9)
    FONT_TITLE  = ("Segoe UI", 10, "bold")

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(self.APP_TITLE)
        self.root.geometry(self.WIN_SIZE)
        self.root.resizable(False, False)
        self.root.configure(bg=self.BG_DARK)

        # ── переменные ──────────────────────────────────────────
        self.v_script   = tk.StringVar(value=_find("deepdrive V2.2", ('.py',)) or
                                             _find("deepdrive",       ('.py',)))
        self.v_name     = tk.StringVar(value="DeepDrive")
        self.v_icon     = tk.StringVar(value=_find("icon", ('.ico',)))
        self.v_yara     = tk.StringVar(value=_find("Rule",  ('.yar','.yara')))
        self.v_usbids   = tk.StringVar(value=_find("usb",   ('.ids',)))
        self.v_presets  = tk.StringVar(value=str(HERE / "DeepDrive_Presets")
                                        if (HERE / "DeepDrive_Presets").is_dir() else "")

        self.v_company  = tk.StringVar(value="Machinist Labs")
        self.v_desc     = tk.StringVar(value="DeepDrive Forensic Toolkit")
        self.v_version  = tk.StringVar(value="2.2.0.0")

        self.v_encrypt  = tk.BooleanVar(value=False)
        self.v_key      = tk.StringVar(value="DD_Secret_2025!")
        self.v_upx      = tk.BooleanVar(value=False)
        self.v_debug    = tk.BooleanVar(value=False)

        self._build_ui()

    # ─────────────────────────────────────────
    #  UI
    # ─────────────────────────────────────────
    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        # общая тёмная тема
        style.configure(".",
            background=self.BG_DARK, foreground="#cccccc",
            font=self.FONT_LABEL, fieldbackground="#12121a")
        style.configure("TLabelframe",
            background=self.BG_DARK, foreground=self.FG_ACCENT,
            bordercolor=self.FG_DIM, relief="flat")
        style.configure("TLabelframe.Label",
            background=self.BG_DARK, foreground=self.FG_ACCENT,
            font=self.FONT_TITLE)
        style.configure("TEntry",
            fieldbackground="#12121a", foreground="#dddddd",
            insertcolor=self.FG_ACCENT, bordercolor=self.FG_DIM)
        style.configure("TCheckbutton",
            background=self.BG_DARK, foreground="#aaaaaa")
        style.configure("Build.TButton",
            background="#1a2a2a", foreground=self.FG_ACCENT,
            font=("Segoe UI", 10, "bold"), padding=8,
            bordercolor=self.FG_ACCENT, relief="flat")
        style.map("Build.TButton",
            background=[("active", "#223333"), ("disabled", "#111118")])

        wrap = tk.Frame(self.root, bg=self.BG_DARK, padx=12, pady=8)
        wrap.pack(fill=tk.BOTH, expand=True)

        # ── шапка ──────────────────────────────────────
        hdr = tk.Frame(wrap, bg=self.BG_DARK)
        hdr.pack(fill=tk.X, pady=(0, 6))
        tk.Label(hdr, text="DEEPDRIVE  BUILDER",
                 bg=self.BG_DARK, fg=self.FG_ACCENT,
                 font=("Consolas", 14, "bold")).pack(side=tk.LEFT)
        tk.Label(hdr, text="V2.2",
                 bg=self.BG_DARK, fg=self.FG_DIM,
                 font=("Consolas", 10)).pack(side=tk.LEFT, padx=8, pady=4)

        # ── блок 1: ресурсы ─────────────────────────────
        lf1 = self._lf(wrap, " РЕСУРСЫ ")
        self._file_row(lf1, 0, "Скрипт (.py):",       self.v_script,  self._pick_script)
        self._file_row(lf1, 1, "Иконка (.ico):",      self.v_icon,    self._pick_icon)
        self._file_row(lf1, 2, "YARA-правила (.yar):", self.v_yara,   self._pick_yara)
        self._file_row(lf1, 3, "usb.ids:",             self.v_usbids, self._pick_usbids)
        self._file_row(lf1, 4, "Папка пресетов:",     self.v_presets, self._pick_presets, folder=True)

        self._row(lf1, 5, "Имя EXE:", self.v_name)

        # ── блок 2: метаданные ──────────────────────────
        lf2 = self._lf(wrap, " МЕТАДАННЫЕ EXE ")
        self._row(lf2, 0, "Компания:",  self.v_company, width=36)
        self._row(lf2, 1, "Описание:",  self.v_desc,   width=36)
        self._row(lf2, 2, "Версия (X.X.X.X):", self.v_version, width=16)

        # ── блок 3: опции ───────────────────────────────
        lf3 = self._lf(wrap, " ОПЦИИ СБОРКИ ")
        r = tk.Frame(lf3, bg=self.BG_DARK); r.pack(fill=tk.X)
        self._chk(r, "UPX-сжатие",      self.v_upx,    side=tk.LEFT)
        self._chk(r, "Отладочная сборка",self.v_debug,  side=tk.LEFT)
        self._chk(r, "Шифровать байт-код (AES)", self.v_encrypt, side=tk.LEFT)
        ttk.Entry(lf3, textvariable=self.v_key, width=28,
                  font=self.FONT_MONO).pack(anchor=tk.W, pady=(2, 0))

        # ── кнопка сборки ───────────────────────────────
        self.btn_build = ttk.Button(
            wrap, text="▶  СОБРАТЬ  DeepDrive.exe",
            style="Build.TButton", command=self._start_build)
        self.btn_build.pack(fill=tk.X, pady=8)

        # ── лог ─────────────────────────────────────────
        self.log_box = ScrolledText(
            wrap, height=11, state=tk.DISABLED,
            bg=self.BG_DARKER, fg=self.FG_OK,
            font=self.FONT_MONO, insertbackground=self.FG_ACCENT,
            relief="flat", bd=0, padx=6, pady=4)
        self.log_box.pack(fill=tk.BOTH, expand=True)
        self.log_box.tag_config("err",  foreground=self.FG_ERR)
        self.log_box.tag_config("warn", foreground=self.FG_WARN)
        self.log_box.tag_config("ok",   foreground=self.FG_OK)
        self.log_box.tag_config("dim",  foreground=self.FG_DIM)
        self.log_box.tag_config("info", foreground=self.FG_ACCENT)

    # ─── UI helpers ───────────────────────────
    def _lf(self, parent, title):
        f = ttk.LabelFrame(parent, text=title, padding=(10, 6))
        f.pack(fill=tk.X, pady=4)
        return f

    def _file_row(self, parent, row, label, var, cmd, folder=False):
        tk.Label(parent, text=label, bg=self.BG_DARK,
                 fg="#999999", font=self.FONT_LABEL,
                 width=22, anchor=tk.W).grid(row=row, column=0, sticky=tk.W, pady=2)
        ttk.Entry(parent, textvariable=var, width=52,
                  font=self.FONT_MONO).grid(row=row, column=1, padx=4, pady=2, sticky=tk.EW)
        ttk.Button(parent, text="…", command=cmd, width=4).grid(row=row, column=2, pady=2)

    def _row(self, parent, row, label, var, width=52):
        tk.Label(parent, text=label, bg=self.BG_DARK,
                 fg="#999999", font=self.FONT_LABEL,
                 width=22, anchor=tk.W).grid(row=row, column=0, sticky=tk.W, pady=2)
        ttk.Entry(parent, textvariable=var, width=width,
                  font=self.FONT_MONO).grid(row=row, column=1, padx=4, pady=2, sticky=tk.W)

    def _chk(self, parent, text, var, side=tk.LEFT):
        ttk.Checkbutton(parent, text=text, variable=var).pack(
            side=side, padx=10, pady=2)

    # ─── файловые диалоги ─────────────────────
    def _pick_script(self):
        p = filedialog.askopenfilename(title="Исходник Python",
            filetypes=[("Python","*.py"),("All","*.*")],
            initialdir=str(HERE))
        if p: self.v_script.set(p)

    def _pick_icon(self):
        p = filedialog.askopenfilename(title="Иконка",
            filetypes=[("Icon","*.ico"),("All","*.*")],
            initialdir=str(HERE))
        if p: self.v_icon.set(p)

    def _pick_yara(self):
        p = filedialog.askopenfilename(title="YARA-правила",
            filetypes=[("YARA","*.yar *.yara"),("All","*.*")],
            initialdir=str(HERE))
        if p: self.v_yara.set(p)

    def _pick_usbids(self):
        p = filedialog.askopenfilename(title="usb.ids",
            filetypes=[("IDS","*.ids"),("All","*.*")],
            initialdir=str(HERE))
        if p: self.v_usbids.set(p)

    def _pick_presets(self):
        p = filedialog.askdirectory(title="Папка пресетов",
            initialdir=str(HERE))
        if p: self.v_presets.set(p)

    # ─────────────────────────────────────────
    #  Логирование
    # ─────────────────────────────────────────
    def _log(self, text: str, tag: str = ""):
        self.root.after(0, self.__append, text, tag)

    def __append(self, text, tag):
        self.log_box.config(state=tk.NORMAL)
        tag = tag or (
            "err"  if any(w in text for w in ("[-]","ОШИБКА","ERROR","error","Error")) else
            "ok"   if any(w in text for w in ("[+]","УСПЕХ","OK","успешно")) else
            "warn" if any(w in text for w in ("[!]","WARNING","Внимание")) else
            "info" if any(w in text for w in ("[*]","[>]","==")) else
            "dim"  if text.startswith("#") else "")
        if tag:
            self.log_box.insert(tk.END, text + "\n", tag)
        else:
            self.log_box.insert(tk.END, text + "\n")
        self.log_box.see(tk.END)
        self.log_box.config(state=tk.DISABLED)

    # ─────────────────────────────────────────
    #  Генерация version-file для PE-метаданных
    # ─────────────────────────────────────────
    def _make_version_file(self, path: str):
        ver = self.v_version.get().strip() or "2.2.0.0"
        parts = [int(x) if x.isdigit() else 0 for x in ver.split(".")]
        while len(parts) < 4: parts.append(0)
        v = ", ".join(map(str, parts))
        name     = self.v_name.get().strip() or "DeepDrive"
        company  = self.v_company.get().strip()
        desc     = self.v_desc.get().strip()

        content = f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({v}), prodvers=({v}),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        StringStruct('CompanyName',      '{company}'),
        StringStruct('FileDescription',  '{desc}'),
        StringStruct('FileVersion',      '{ver}'),
        StringStruct('InternalName',     '{name}'),
        StringStruct('LegalCopyright',   '\\xa9 {company}. All rights reserved.'),
        StringStruct('OriginalFilename', '{name}.exe'),
        StringStruct('ProductName',      '{desc}'),
        StringStruct('ProductVersion',   '{ver}'),
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
        Path(path).write_text(content, encoding="utf-8")

    # ─────────────────────────────────────────
    #  Запуск сборки
    # ─────────────────────────────────────────
    def _start_build(self):
        script = self.v_script.get().strip()
        if not script or not Path(script).is_file():
            messagebox.showerror("Ошибка", "Укажите корректный путь к .py файлу!")
            return
        self.btn_build.config(state=tk.DISABLED)
        self.log_box.config(state=tk.NORMAL)
        self.log_box.delete("1.0", tk.END)
        self.log_box.config(state=tk.DISABLED)
        threading.Thread(target=self._build, daemon=True).start()

    def _run(self, cmd: list) -> int:
        si = subprocess.STARTUPINFO() if os.name == "nt" else None
        if si: si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            startupinfo=si, bufsize=1, cwd=str(HERE))
        for line in proc.stdout:
            line = line.rstrip()
            if line: self._log(line)
        proc.stdout.close()
        return proc.wait()

    def _build(self):
        ver_file  = str(HERE / "_version_info.txt")
        name      = self.v_name.get().strip() or "DeepDrive"
        script    = self.v_script.get().strip()
        icon      = self.v_icon.get().strip()
        yara      = self.v_yara.get().strip()
        usbids    = self.v_usbids.get().strip()
        presets   = self.v_presets.get().strip()
        sep       = ";" if os.name == "nt" else ":"

        try:
            # 1. Проверка PyInstaller
            self._log("[*] Проверка PyInstaller...")
            r = subprocess.run([sys.executable, "-m", "PyInstaller", "--version"],
                               capture_output=True, text=True)
            pi_ver = r.stdout.strip() if r.returncode == 0 else "0.0.0"

            if r.returncode != 0:
                self._log("[!] PyInstaller не найден — устанавливаю...", "warn")
                self._run([sys.executable, "-m", "pip", "install", "pyinstaller"])
                # Re-check version
                r = subprocess.run([sys.executable, "-m", "PyInstaller", "--version"],
                                   capture_output=True, text=True)
                pi_ver = r.stdout.strip() if r.returncode == 0 else "0.0.0"
            
            self._log(f"[*] PyInstaller version: {pi_ver}", "info")

            # 2. Шифрование (tinyaes)
            if self.v_encrypt.get():
                self._log("[*] Установка tinyaes для шифрования байт-кода...")
                self._run([sys.executable, "-m", "pip", "install", "tinyaes"])

            # 3. version-файл
            self._log("[*] Генерация PE-метаданных...")
            self._make_version_file(ver_file)

            # 4. Команда PyInstaller
            cmd = [
                sys.executable, "-m", "PyInstaller",
                "--onefile",
                "--console",
                "--clean",
                f"--name={name}",
                f"--version-file={ver_file}",
                # hidden imports — все что используется в DeepDrive
                "--hidden-import=yara",
                "--hidden-import=msvcrt",
                "--hidden-import=ctypes",
                "--hidden-import=ctypes.wintypes",
                "--hidden-import=winreg",
                "--hidden-import=subprocess",
                "--hidden-import=threading",
                "--hidden-import=hashlib",
                "--hidden-import=logging",
                "--hidden-import=urllib.request",
                "--hidden-import=collections",
                "--hidden-import=tempfile",
                "--hidden-import=pathlib",
                "--hidden-import=csv",
                "--hidden-import=struct",
            ]

            if not self.v_upx.get():
                cmd.append("--noupx")

            if self.v_debug.get():
                cmd.append("--debug=all")

            if icon and Path(icon).is_file():
                cmd.append(f"--icon={icon}")

            # -- YARA-правила --
            if yara and Path(yara).is_file():
                yara_dest = Path(HERE) / Path(yara).name
                if Path(yara).resolve() != yara_dest.resolve():
                    shutil.copy(yara, str(yara_dest))
                cmd.append(f"--add-data={yara_dest}{sep}.")
                self._log(f"[+] YARA: {Path(yara).name}")

            # -- usb.ids --
            if usbids and Path(usbids).is_file():
                cmd.append(f"--add-data={usbids}{sep}.")
                self._log(f"[+] usb.ids: {Path(usbids).name}")

            # -- папка пресетов --
            if presets and Path(presets).is_dir():
                # Копируем папку внутрь exe как DeepDrive_Presets/
                presets_dest = Path(presets).name  # "DeepDrive_Presets"
                cmd.append(f"--add-data={presets}{sep}{presets_dest}")
                self._log(f"[+] Пресеты: {presets_dest}/ ({len(list(Path(presets).glob('*.json')))} файлов)")

            if self.v_encrypt.get() and self.v_key.get().strip():
                try:
                    major_ver = int(pi_ver.split('.')[0])
                except (ValueError, IndexError):
                    major_ver = 0

                if major_ver > 0 and major_ver < 6:
                    cmd.append(f"--key={self.v_key.get().strip()}")
                    self._log("[+] Байт-код будет зашифрован (AES)", "warn")
                else:
                    self._log("[!] PyInstaller 6.0+ больше не поддерживает шифрования (--key). Пропускаю.", "err")
                    self._log("    (см. https://github.com/pyinstaller/pyinstaller/pull/6999)", "dim")

            cmd.append(script)

            # 5. Сборка
            self._log("\n[*] Запуск PyInstaller...\n" + "═" * 54, "info")
            ret = self._run(cmd)
            self._log("═" * 54, "info")

            if ret == 0:
                dist_exe = HERE / "dist" / f"{name}.exe"
                self._log(f"\n[+] ГОТОВО!  {dist_exe}", "ok")
                self._log(f"[+] Размер: {dist_exe.stat().st_size / 1_048_576:.1f} МБ", "ok")
                self.root.after(0, self._done_dialog, str(HERE / "dist"))
            else:
                self._log(f"\n[-] Сборка завершилась с кодом {ret}.", "err")

        except Exception as e:
            self._log(f"\n[-] КРИТИЧЕСКАЯ ОШИБКА: {e}", "err")
            import traceback
            self._log(traceback.format_exc(), "dim")

        finally:
            # Чистим временные файлы
            for tmp in [ver_file,
                        str(HERE / f"{name}.spec"),
                        str(HERE / "Rule.yar") if yara and Path(yara).resolve() != (HERE / Path(yara).name).resolve() else ""]:
                if tmp and Path(tmp).exists():
                    try: Path(tmp).unlink()
                    except: pass
            shutil.rmtree(str(HERE / "build"), ignore_errors=True)
            self.root.after(0, lambda: self.btn_build.config(state=tk.NORMAL))

    def _done_dialog(self, dist_path: str):
        if messagebox.askyesno(
                "✔  Сборка завершена",
                f"EXE успешно создан!\n\nОткрыть папку dist/?"):
            if os.name == "nt":
                os.startfile(dist_path)


# ─────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    app  = DeepDriveBuilder(root)
    root.mainloop()