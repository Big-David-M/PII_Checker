"""
UAC // PII SCANNER v1.1 — SECURITY TERMINAL
Paste text, scan for PII/secrets locally, send clean text to CoCo.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import json
import os
import sys
from pathlib import Path

from pii_patterns import scan_text, get_all_pattern_names, PiiMatch

CONFIG_FILE = Path.home() / ".pii_checker_config.json"

DEFAULT_CONFIG = {
    "coco_cli_path": "cortex",
    "min_confidence": "low",
    "disabled_patterns": [],
    "window_width": 940,
    "window_height": 800,
}

# ============================================================
# UAC / DOOM / QUAKE PALETTE
# ============================================================

METAL_DARK   = "#0b0b0b"
METAL_MID    = "#181818"
METAL_LIGHT  = "#292929"
METAL_BORDER = "#55504a"

RUST         = "#8f3f16"
RUST_LIGHT   = "#c06020"
RUST_DIM     = "#48200e"

RIVET        = "#66615a"

TEXT_GREEN   = "#32ff32"
TEXT_AMBER   = "#ffb000"
TEXT_RED     = "#ff2020"
TEXT_DIM     = "#555555"
TEXT_BRIGHT  = "#d0c8b8"

HUD_BG       = "#080808"
BLOOD_RED    = "#b00000"

DOOM_FONT      = "Courier New"
DOOM_FONT_BOLD = (DOOM_FONT, 10, "bold")

TAG_COLORS = {
    "high":   {"bg": "#b00000", "fg": "#ffffff"},
    "medium": {"bg": "#a64b00", "fg": "#ffffcc"},
    "low":    {"bg": "#333333", "fg": "#cccccc"},
}


class Config:
    def __init__(self):
        self.data = dict(DEFAULT_CONFIG)
        self.load()

    def load(self):
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r") as f:
                    saved = json.load(f)
                self.data.update(saved)
            except (json.JSONDecodeError, IOError):
                pass

    def save(self):
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self.data, f, indent=2)
        except IOError:
            pass

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value


def doom_button(parent, text, command, state="normal"):
    btn = tk.Button(
        parent,
        text=text.upper(),
        command=command,
        state=state,
        font=(DOOM_FONT, 9, "bold"),
        fg=TEXT_AMBER,
        bg=METAL_LIGHT,
        activebackground=RUST_LIGHT,
        activeforeground="#ffffff",
        disabledforeground="#444444",
        relief="raised",
        bd=2,
        highlightbackground=METAL_BORDER,
        highlightcolor=RUST,
        padx=12,
        pady=5,
        cursor="hand2",
    )
    return btn


class SettingsWindow(tk.Toplevel):
    def __init__(self, parent, config: Config, on_save):
        super().__init__(parent)
        self.title("// UAC CONFIG TERMINAL //")
        self.config = config
        self.on_save = on_save
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.configure(bg=METAL_DARK)

        self.pattern_vars = {}
        self._build_ui()
        self.geometry("+%d+%d" % (parent.winfo_x() + 50, parent.winfo_y() + 50))

    def _build_ui(self):
        gen_frame = tk.LabelFrame(self, text=" GENERAL ", font=(DOOM_FONT, 10, "bold"),
                                  fg=TEXT_AMBER, bg=METAL_DARK, bd=2, relief="ridge",
                                  highlightbackground=RUST_DIM)
        gen_frame.pack(fill="x", padx=10, pady=(10, 5))

        tk.Label(gen_frame, text="COCO CLI PATH:", font=(DOOM_FONT, 9),
                 fg=TEXT_GREEN, bg=METAL_DARK).grid(row=0, column=0, sticky="w", pady=5, padx=5)
        self.cli_var = tk.StringVar(value=self.config["coco_cli_path"])
        tk.Entry(gen_frame, textvariable=self.cli_var, width=35,
                 font=(DOOM_FONT, 10), fg=TEXT_GREEN, bg=HUD_BG,
                 insertbackground=TEXT_GREEN, relief="sunken", bd=2).grid(row=0, column=1, pady=5, padx=5)

        tk.Label(gen_frame, text="MIN CONFIDENCE:", font=(DOOM_FONT, 9),
                 fg=TEXT_GREEN, bg=METAL_DARK).grid(row=1, column=0, sticky="w", pady=5, padx=5)
        self.conf_var = tk.StringVar(value=self.config["min_confidence"])
        conf_menu = tk.OptionMenu(gen_frame, self.conf_var, "low", "medium", "high")
        conf_menu.configure(font=(DOOM_FONT, 9), fg=TEXT_GREEN, bg=METAL_LIGHT,
                           activebackground=RUST, highlightbackground=METAL_BORDER)
        conf_menu.grid(row=1, column=1, sticky="w", pady=5, padx=5)

        pat_frame = tk.LabelFrame(self, text=" DETECTION MODULES ", font=(DOOM_FONT, 10, "bold"),
                                  fg=TEXT_AMBER, bg=METAL_DARK, bd=2, relief="ridge",
                                  highlightbackground=RUST_DIM)
        pat_frame.pack(fill="both", expand=True, padx=10, pady=5)

        canvas = tk.Canvas(pat_frame, bg=METAL_DARK, highlightthickness=0, width=420, height=300)
        scrollbar = tk.Scrollbar(pat_frame, orient="vertical", command=canvas.yview,
                                 bg=METAL_MID, troughcolor=METAL_DARK)
        inner = tk.Frame(canvas, bg=METAL_DARK)

        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        disabled = set(self.config["disabled_patterns"])
        all_patterns = get_all_pattern_names()

        current_cat = None
        for name, category, confidence in all_patterns:
            if category != current_cat:
                current_cat = category
                tk.Label(inner, text=f"=== {category.upper()} ===",
                         font=(DOOM_FONT, 10, "bold"), fg=RUST_LIGHT,
                         bg=METAL_DARK).pack(anchor="w", pady=(8, 2), padx=5)

            var = tk.BooleanVar(value=(name not in disabled))
            self.pattern_vars[name] = var
            cb = tk.Checkbutton(inner, text=f"{name}  [{confidence}]", variable=var,
                                font=(DOOM_FONT, 9), fg=TEXT_DIM, bg=METAL_DARK,
                                selectcolor=METAL_MID, activebackground=METAL_DARK,
                                activeforeground=TEXT_GREEN)
            cb.pack(anchor="w", padx=20)

        btn_frame = tk.Frame(self, bg=METAL_DARK)
        btn_frame.pack(fill="x", padx=10, pady=10)
        doom_button(btn_frame, "SAVE", self._save).pack(side="right", padx=5)
        doom_button(btn_frame, "CANCEL", self.destroy).pack(side="right")

    def _save(self):
        self.config["coco_cli_path"] = self.cli_var.get().strip() or "cortex"
        self.config["min_confidence"] = self.conf_var.get()
        disabled = [name for name, var in self.pattern_vars.items() if not var.get()]
        self.config["disabled_patterns"] = disabled
        self.config.save()
        self.on_save()
        self.destroy()


class PiiCheckerApp:
    DOT_GRAY  = TEXT_DIM
    DOT_GREEN = TEXT_GREEN
    DOT_RED   = TEXT_RED
    DOT_AMBER = TEXT_AMBER

    def __init__(self, root: tk.Tk):
        self.root = root
        self.config = Config()
        self.matches: list = []
        self._scan_after_id = None
        self._blink_after_id = None
        self._blink_state = False

        self.root.title("UAC // PII SCANNER // SECURITY TERMINAL")
        self.root.geometry(f"{self.config['window_width']}x{self.config['window_height']}")
        self.root.minsize(700, 550)
        self.root.configure(bg=METAL_DARK)

        self._build_ui()
        self._apply_tags()

    def _build_ui(self):
        # -- Title plate (riveted metal) --
        title_frame = tk.Frame(self.root, bg=METAL_DARK)
        title_frame.pack(fill="x", padx=6, pady=(6, 2))

        title_plate = tk.Canvas(title_frame, height=52, bg=METAL_MID,
                                highlightthickness=1, highlightbackground=RUST_DIM,
                                relief="raised", bd=2)
        title_plate.pack(fill="x")
        title_plate.bind("<Configure>", lambda e: self._on_title_resize(e, title_plate))

        self.dot_id = title_plate.create_oval(16, 14, 38, 36,
                                               fill=self.DOT_GRAY, outline=METAL_BORDER, width=2)
        title_plate.create_text(48, 18, text="UAC // PII SCANNER",
                               font=(DOOM_FONT, 14, "bold"), fill=TEXT_AMBER, anchor="w")
        title_plate.create_text(48, 36, text="SECURITY TERMINAL // SECTOR 07",
                               font=(DOOM_FONT, 8), fill=RUST_LIGHT, anchor="w")

        self.dot_text_id = title_plate.create_text(310, 26, text="[ AWAITING INPUT ]",
                                                    font=(DOOM_FONT, 10, "bold"), fill=TEXT_DIM, anchor="w")
        self.title_plate = title_plate

        settings_btn = doom_button(title_frame, "CONFIG", self._open_settings)
        settings_btn.place(relx=1.0, rely=0.5, anchor="e", x=-12)

        # -- Threat counter bar --
        threat_bar = tk.Frame(self.root, bg=METAL_DARK)
        threat_bar.pack(fill="x", padx=6, pady=(0, 2))

        threat_plate = tk.Canvas(threat_bar, height=26, bg=METAL_DARK,
                                 highlightthickness=1, highlightbackground=RUST_DIM,
                                 relief="sunken", bd=1)
        threat_plate.pack(fill="x")

        threat_plate.create_text(10, 13, text="STATUS:",
                                font=(DOOM_FONT, 9, "bold"), fill=TEXT_DIM, anchor="w")
        self.status_text_id = threat_plate.create_text(80, 13, text="SYSTEM ACTIVE",
                                                        font=(DOOM_FONT, 9, "bold"), fill=TEXT_GREEN, anchor="w")
        threat_plate.create_text(350, 13, text="THREATS:",
                                font=(DOOM_FONT, 9, "bold"), fill=TEXT_DIM, anchor="w")
        self.threat_count_id = threat_plate.create_text(430, 13, text="[ 00 ]",
                                                         font=(DOOM_FONT, 9, "bold"), fill=TEXT_GREEN, anchor="w")
        self.threat_plate = threat_plate

        # -- Input panel --
        input_outer = tk.Frame(self.root, bg=RUST_DIM, bd=2, relief="ridge")
        input_outer.pack(fill="both", expand=True, padx=6, pady=2)

        input_header = tk.Frame(input_outer, bg=METAL_MID, height=22)
        input_header.pack(fill="x")
        input_header.pack_propagate(False)
        tk.Label(input_header, text=" >> INPUT BUFFER",
                 font=(DOOM_FONT, 8, "bold"), fg=RUST_LIGHT, bg=METAL_MID,
                 anchor="w").pack(fill="x", padx=4)

        self.text_area = scrolledtext.ScrolledText(
            input_outer, wrap="word",
            font=(DOOM_FONT, 10), undo=True,
            bg=HUD_BG, fg=TEXT_GREEN,
            insertbackground=TEXT_GREEN,
            selectbackground=RUST, selectforeground=TEXT_BRIGHT,
            relief="sunken", bd=2,
            highlightbackground=METAL_BORDER, highlightcolor=RUST,
        )
        self.text_area.pack(fill="both", expand=True, padx=2, pady=(0, 2))
        self.text_area.bind("<<Modified>>", self._on_text_changed)
        self.text_area.bind("<Control-v>", self._on_paste)

        # -- Button strip --
        btn_strip = tk.Frame(self.root, bg=METAL_MID, bd=1, relief="raised")
        btn_strip.pack(fill="x", padx=6, pady=2)

        self.scan_btn = doom_button(btn_strip, ">> SCAN", self._scan)
        self.scan_btn.pack(side="left", padx=4, pady=3)

        self.clear_btn = doom_button(btn_strip, "CLEAR", self._clear)
        self.clear_btn.pack(side="left", padx=2, pady=3)

        self.copy_btn = doom_button(btn_strip, "COPY TO CLIPBOARD", self._copy_to_clipboard, state="disabled")
        self.copy_btn.pack(side="right", padx=4, pady=3)

        self.send_btn = doom_button(btn_strip, "SEND TO COCO", self._send_to_coco, state="disabled")
        self.send_btn.pack(side="right", padx=2, pady=3)

        # -- Results panel --
        results_outer = tk.Frame(self.root, bg=RUST_DIM, bd=2, relief="ridge")
        results_outer.pack(fill="both", padx=6, pady=2, expand=False)

        results_header = tk.Frame(results_outer, bg=METAL_MID, height=22)
        results_header.pack(fill="x")
        results_header.pack_propagate(False)
        self.results_header_label = tk.Label(results_header, text=" >> THREAT ANALYSIS",
                 font=(DOOM_FONT, 8, "bold"), fg=RUST_LIGHT, bg=METAL_MID,
                 anchor="w")
        self.results_header_label.pack(fill="x", padx=4)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Doom.Treeview",
                        background=HUD_BG, foreground=TEXT_GREEN,
                        fieldbackground=HUD_BG, font=(DOOM_FONT, 9),
                        rowheight=21, borderwidth=1, relief="flat")
        style.configure("Doom.Treeview.Heading",
                        background=METAL_MID, foreground=TEXT_AMBER,
                        font=(DOOM_FONT, 9, "bold"), relief="raised",
                        borderwidth=2, padding=(6, 4))
        style.map("Doom.Treeview",
                  background=[("selected", RUST)],
                  foreground=[("selected", "#ffffff")])

        self.results_tree = ttk.Treeview(results_outer, style="Doom.Treeview",
                                         columns=("type", "confidence", "category", "text"),
                                         show="headings", height=6)
        self.results_tree.heading("type", text="TYPE")
        self.results_tree.heading("confidence", text="LEVEL")
        self.results_tree.heading("category", text="CLASS")
        self.results_tree.heading("text", text="INTERCEPTED DATA")
        self.results_tree.column("type", width=160)
        self.results_tree.column("confidence", width=90)
        self.results_tree.column("category", width=80)
        self.results_tree.column("text", width=400)

        tree_scroll = tk.Scrollbar(results_outer, orient="vertical",
                                   command=self.results_tree.yview,
                                   bg=METAL_MID, troughcolor=HUD_BG)
        self.results_tree.configure(yscrollcommand=tree_scroll.set)
        self.results_tree.pack(side="left", fill="both", expand=True, padx=2, pady=(0, 2))
        tree_scroll.pack(side="right", fill="y", pady=(0, 2))

        self.results_tree.bind("<<TreeviewSelect>>", self._on_result_click)

        # -- HUD status bar --
        hud_outer = tk.Frame(self.root, bg=RUST_DIM, bd=2, relief="ridge")
        hud_outer.pack(fill="x", padx=6, pady=(2, 6))

        self.status_var = tk.StringVar(value="UAC SECURITY TERMINAL // ONLINE // Paste data into input buffer...")
        self.status_bar = tk.Label(hud_outer, textvariable=self.status_var,
                                   font=(DOOM_FONT, 9, "bold"),
                                   fg=TEXT_GREEN, bg=HUD_BG,
                                   anchor="w", padx=8, pady=4)
        self.status_bar.pack(fill="x")

    def _on_title_resize(self, event, canvas):
        w, h = event.width, event.height
        canvas.delete("rivet")
        rs = 7
        for x, y in [(5, 5), (w-14, 5), (5, h-14), (w-14, h-14),
                      (w//2 - 3, 5), (w//2 - 3, h-14)]:
            canvas.create_oval(x, y, x+rs, y+rs, fill=RIVET, outline="#777777", tags="rivet")
            canvas.create_oval(x+2, y+2, x+rs-2, y+rs-2, fill="#444444", outline="", tags="rivet")

    def _apply_tags(self):
        for level, colors in TAG_COLORS.items():
            self.text_area.tag_configure(f"pii_{level}", background=colors["bg"], foreground=colors["fg"])
        self.text_area.tag_configure("selected_pii", background="#ff00ff", foreground="#ffffff")

    def _get_enabled_patterns(self):
        all_names = {name for name, _, _ in get_all_pattern_names()}
        disabled = set(self.config["disabled_patterns"])
        return all_names - disabled

    def _set_dot(self, color, text):
        self.title_plate.itemconfig(self.dot_id, fill=color)
        self.title_plate.itemconfig(self.dot_text_id, text=text, fill=color)

    def _start_blink(self):
        self._stop_blink()
        self._blink_state = True
        self._blink()

    def _stop_blink(self):
        if self._blink_after_id:
            self.root.after_cancel(self._blink_after_id)
            self._blink_after_id = None
        self._blink_state = False

    def _blink(self):
        if not self._blink_state:
            return
        current = self.title_plate.itemcget(self.dot_id, "fill")
        next_color = BLOOD_RED if current == TEXT_RED else TEXT_RED
        self.title_plate.itemconfig(self.dot_id, fill=next_color)
        self._blink_after_id = self.root.after(500, self._blink)

    def _on_text_changed(self, event=None):
        self.text_area.edit_modified(False)
        self._schedule_auto_scan()

    def _on_paste(self, event=None):
        self._schedule_auto_scan()

    def _schedule_auto_scan(self):
        if self._scan_after_id:
            self.root.after_cancel(self._scan_after_id)
        self._scan_after_id = self.root.after(400, self._scan)

    def _scan(self):
        text = self.text_area.get("1.0", "end-1c")
        if not text.strip():
            self._stop_blink()
            self.status_var.set("UAC SECURITY TERMINAL // ONLINE // Paste data into input buffer...")
            self.status_bar.configure(fg=TEXT_GREEN)
            self._set_dot(self.DOT_GRAY, "[ AWAITING INPUT ]")
            self.threat_plate.itemconfig(self.status_text_id, text="SYSTEM ACTIVE", fill=TEXT_GREEN)
            self.threat_plate.itemconfig(self.threat_count_id, text="[ 00 ]", fill=TEXT_GREEN)
            self.results_header_label.configure(text=" >> THREAT ANALYSIS")
            return

        self._stop_blink()
        self._set_dot(self.DOT_AMBER, "[ SCANNING... ]")
        self.status_var.set("[ SCANNING ] Analyzing input buffer for PII signatures...")
        self.status_bar.configure(fg=TEXT_AMBER)
        self.threat_plate.itemconfig(self.status_text_id, text="SCANNING", fill=TEXT_AMBER)
        self.root.update_idletasks()

        for level in TAG_COLORS:
            self.text_area.tag_remove(f"pii_{level}", "1.0", "end")
        self.text_area.tag_remove("selected_pii", "1.0", "end")
        self.results_tree.delete(*self.results_tree.get_children())

        enabled = self._get_enabled_patterns()
        self.matches = scan_text(text, enabled_patterns=enabled, min_confidence=self.config["min_confidence"])

        for match in self.matches:
            start_idx = f"1.0+{match.start}c"
            end_idx = f"1.0+{match.end}c"
            tag = f"pii_{match.confidence}"
            self.text_area.tag_add(tag, start_idx, end_idx)

            level_display = match.confidence.upper()
            if match.confidence == "high":
                level_display = "!!! HIGH !!!"
            elif match.confidence == "medium":
                level_display = "!! WARN !!"

            display_text = match.text if len(match.text) <= 55 else match.text[:52] + "..."
            self.results_tree.insert("", "end", values=(
                match.pattern_name,
                level_display,
                match.category.upper(),
                display_text,
            ))

        count = len(self.matches)
        if count == 0:
            self._stop_blink()
            self._set_dot(self.DOT_GREEN, "[ ALL CLEAR ]")
            self.status_var.set("[ SECURE ] No PII detected // Buffer is clean // Ready to transmit")
            self.status_bar.configure(fg=TEXT_GREEN)
            self.threat_plate.itemconfig(self.status_text_id, text="SECURE", fill=TEXT_GREEN)
            self.threat_plate.itemconfig(self.threat_count_id, text="[ 00 ]", fill=TEXT_GREEN)
            self.results_header_label.configure(text=" >> THREAT ANALYSIS // STATUS: CLEAR")
            self.copy_btn.configure(state="normal")
            self.send_btn.configure(state="normal")
        else:
            high = sum(1 for m in self.matches if m.confidence == "high")
            med = sum(1 for m in self.matches if m.confidence == "medium")
            low = sum(1 for m in self.matches if m.confidence == "low")
            parts = []
            if high:
                parts.append(f"{high} CRIT")
            if med:
                parts.append(f"{med} WARN")
            if low:
                parts.append(f"{low} LOW")
            threat_str = " / ".join(parts)
            count_str = f"[ {count:02d} ]"

            self._set_dot(self.DOT_RED, f"[ {count} THREAT(S) DETECTED ]")
            self._start_blink()
            self.status_var.set(f"[ BLOCKED ] {count} PII target(s) intercepted: {threat_str} -- TRANSMISSION DENIED")
            self.status_bar.configure(fg=TEXT_RED)
            self.threat_plate.itemconfig(self.status_text_id, text="HOSTILE", fill=TEXT_RED)
            self.threat_plate.itemconfig(self.threat_count_id, text=count_str, fill=TEXT_RED)
            self.results_header_label.configure(text=f" >> THREAT ANALYSIS // STATUS: [ HOSTILE ]")
            self.copy_btn.configure(state="disabled")
            self.send_btn.configure(state="disabled")

    def _on_result_click(self, event):
        sel = self.results_tree.selection()
        if not sel:
            return
        idx = self.results_tree.index(sel[0])
        if idx < len(self.matches):
            match = self.matches[idx]
            self.text_area.tag_remove("selected_pii", "1.0", "end")
            start_idx = f"1.0+{match.start}c"
            end_idx = f"1.0+{match.end}c"
            self.text_area.tag_add("selected_pii", start_idx, end_idx)
            self.text_area.tag_raise("selected_pii")
            self.text_area.see(start_idx)

    def _clear(self):
        self._stop_blink()
        self.text_area.delete("1.0", "end")
        for level in TAG_COLORS:
            self.text_area.tag_remove(f"pii_{level}", "1.0", "end")
        self.text_area.tag_remove("selected_pii", "1.0", "end")
        self.results_tree.delete(*self.results_tree.get_children())
        self.matches = []
        self._set_dot(self.DOT_GRAY, "[ AWAITING INPUT ]")
        self.status_var.set("UAC SECURITY TERMINAL // ONLINE // Input buffer cleared")
        self.status_bar.configure(fg=TEXT_GREEN)
        self.threat_plate.itemconfig(self.status_text_id, text="SYSTEM ACTIVE", fill=TEXT_GREEN)
        self.threat_plate.itemconfig(self.threat_count_id, text="[ 00 ]", fill=TEXT_GREEN)
        self.results_header_label.configure(text=" >> THREAT ANALYSIS")
        self.copy_btn.configure(state="disabled")
        self.send_btn.configure(state="disabled")

    def _copy_to_clipboard(self):
        text = self.text_area.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("[ COPIED ] Buffer contents loaded to clipboard // Transmit when ready")

    def _send_to_coco(self):
        text = self.text_area.get("1.0", "end-1c")
        cli = self.config["coco_cli_path"]
        try:
            result = subprocess.run(
                [cli, "send", "--text", text],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                self.status_var.set("[ TRANSMITTED ] Data sent to CoCo successfully // Link secure")
            else:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                self.status_var.set(f"[ FALLBACK ] CoCo link failed // Copied to clipboard // ERR: {result.stderr.strip()[:60]}")
        except FileNotFoundError:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_var.set(f"[ FALLBACK ] CoCo not found at '{cli}' // Copied to clipboard // Set path in CONFIG")
        except subprocess.TimeoutExpired:
            self.status_var.set("[ TIMEOUT ] CoCo link timed out")
        except Exception as e:
            self.status_var.set(f"[ ERROR ] {str(e)[:100]}")

    def _open_settings(self):
        SettingsWindow(self.root, self.config, on_save=self._on_settings_saved)

    def _on_settings_saved(self):
        self.status_var.set("[ CONFIG SAVED ] Detection modules updated // Re-scanning...")
        self.status_bar.configure(fg=TEXT_AMBER)
        self.root.after(300, self._scan)


def main():
    root = tk.Tk()
    root.configure(bg=METAL_DARK)
    app = PiiCheckerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
