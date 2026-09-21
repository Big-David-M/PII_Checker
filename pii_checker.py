"""
PII Checker — standalone desktop app.
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
    "window_width": 900,
    "window_height": 750,
}

TAG_COLORS = {
    "high": {"bg": "#FF6B6B", "fg": "#000000"},
    "medium": {"bg": "#FFD93D", "fg": "#000000"},
    "low": {"bg": "#6BCFFF", "fg": "#000000"},
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


class SettingsWindow(tk.Toplevel):
    def __init__(self, parent, config: Config, on_save):
        super().__init__(parent)
        self.title("Settings")
        self.config = config
        self.on_save = on_save
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.pattern_vars = {}
        self._build_ui()
        self.geometry("+%d+%d" % (parent.winfo_x() + 50, parent.winfo_y() + 50))

    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        general = ttk.Frame(notebook, padding=10)
        notebook.add(general, text="General")

        ttk.Label(general, text="CoCo CLI path:").grid(row=0, column=0, sticky="w", pady=5)
        self.cli_var = tk.StringVar(value=self.config["coco_cli_path"])
        ttk.Entry(general, textvariable=self.cli_var, width=40).grid(row=0, column=1, sticky="w", pady=5, padx=5)

        ttk.Label(general, text="Minimum confidence:").grid(row=1, column=0, sticky="w", pady=5)
        self.conf_var = tk.StringVar(value=self.config["min_confidence"])
        conf_combo = ttk.Combobox(general, textvariable=self.conf_var, values=["low", "medium", "high"], state="readonly", width=10)
        conf_combo.grid(row=1, column=1, sticky="w", pady=5, padx=5)

        patterns_frame = ttk.Frame(notebook, padding=10)
        notebook.add(patterns_frame, text="Patterns")

        canvas = tk.Canvas(patterns_frame, width=400, height=350)
        scrollbar = ttk.Scrollbar(patterns_frame, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)

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
                lbl = ttk.Label(inner, text=f"-- {category.upper()} --", font=("TkDefaultFont", 10, "bold"))
                lbl.pack(anchor="w", pady=(10, 2))

            var = tk.BooleanVar(value=(name not in disabled))
            self.pattern_vars[name] = var
            cb = ttk.Checkbutton(inner, text=f"{name}  ({confidence})", variable=var)
            cb.pack(anchor="w", padx=15)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=10)
        ttk.Button(btn_frame, text="Save", command=self._save).pack(side="right", padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side="right")

    def _save(self):
        self.config["coco_cli_path"] = self.cli_var.get().strip() or "cortex"
        self.config["min_confidence"] = self.conf_var.get()
        disabled = [name for name, var in self.pattern_vars.items() if not var.get()]
        self.config["disabled_patterns"] = disabled
        self.config.save()
        self.on_save()
        self.destroy()


class PiiCheckerApp:
    DOT_GRAY = "#999999"
    DOT_GREEN = "#22c55e"
    DOT_RED = "#ef4444"
    DOT_BLUE = "#3b82f6"

    def __init__(self, root: tk.Tk):
        self.root = root
        self.config = Config()
        self.matches: list = []
        self._scan_after_id = None

        self.root.title("PII Checker")
        self.root.geometry(f"{self.config['window_width']}x{self.config['window_height']}")
        self.root.minsize(600, 500)

        self._build_ui()
        self._apply_tags()

    def _build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # -- Top bar with status dot --
        top = tk.Frame(self.root)
        top.pack(fill="x", padx=10, pady=(10, 5))

        self.dot_canvas = tk.Canvas(top, width=20, height=20, highlightthickness=0)
        self.dot_canvas.pack(side="left", padx=(0, 6))
        self.dot_id = self.dot_canvas.create_oval(2, 2, 18, 18, fill=self.DOT_GRAY, outline="")

        self.title_label = tk.Label(top, text="PII Checker", font=("TkDefaultFont", 16, "bold"))
        self.title_label.pack(side="left")

        self.dot_text = tk.Label(top, text="Waiting for input", font=("TkDefaultFont", 10), fg="#666666")
        self.dot_text.pack(side="left", padx=(10, 0))

        ttk.Button(top, text="Settings", command=self._open_settings, width=8).pack(side="right")

        # -- Input area --
        input_frame = ttk.LabelFrame(self.root, text="Paste text here", padding=5)
        input_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.text_area = scrolledtext.ScrolledText(input_frame, wrap="word", font=("Consolas", 11), undo=True)
        self.text_area.pack(fill="both", expand=True)
        self.text_area.bind("<<Modified>>", self._on_text_changed)
        self.text_area.bind("<Control-v>", self._on_paste)

        # -- Button bar --
        btn_bar = ttk.Frame(self.root)
        btn_bar.pack(fill="x", padx=10, pady=5)

        self.scan_btn = ttk.Button(btn_bar, text="Scan for PII", command=self._scan)
        self.scan_btn.pack(side="left", padx=(0, 5))

        self.clear_btn = ttk.Button(btn_bar, text="Clear", command=self._clear)
        self.clear_btn.pack(side="left")

        self.copy_btn = ttk.Button(btn_bar, text="Copy to Clipboard", command=self._copy_to_clipboard, state="disabled")
        self.copy_btn.pack(side="right", padx=(5, 0))

        self.send_btn = ttk.Button(btn_bar, text="Send to CoCo", command=self._send_to_coco, state="disabled")
        self.send_btn.pack(side="right")

        # -- Results area --
        results_frame = ttk.LabelFrame(self.root, text="Results", padding=5)
        results_frame.pack(fill="both", padx=10, pady=(5, 5), expand=False)
        results_frame.configure(height=180)

        self.results_tree = ttk.Treeview(results_frame, columns=("type", "confidence", "category", "text"), show="headings", height=6)
        self.results_tree.heading("type", text="Type")
        self.results_tree.heading("confidence", text="Confidence")
        self.results_tree.heading("category", text="Category")
        self.results_tree.heading("text", text="Matched Text")
        self.results_tree.column("type", width=150)
        self.results_tree.column("confidence", width=80)
        self.results_tree.column("category", width=80)
        self.results_tree.column("text", width=400)

        tree_scroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=tree_scroll.set)
        self.results_tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")

        self.results_tree.bind("<<TreeviewSelect>>", self._on_result_click)

        # -- Status bar --
        self.status_var = tk.StringVar(value="Paste text and press Scan, or just start typing.")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w", padding=5)
        self.status_bar.pack(fill="x", padx=10, pady=(0, 10))

    def _apply_tags(self):
        for level, colors in TAG_COLORS.items():
            self.text_area.tag_configure(f"pii_{level}", background=colors["bg"], foreground=colors["fg"])
        self.text_area.tag_configure("selected_pii", background="#B833FF", foreground="#FFFFFF")

    def _get_enabled_patterns(self):
        all_names = {name for name, _, _ in get_all_pattern_names()}
        disabled = set(self.config["disabled_patterns"])
        return all_names - disabled

    def _set_dot(self, color, text):
        self.dot_canvas.itemconfig(self.dot_id, fill=color)
        self.dot_text.configure(text=text, fg=color if color != self.DOT_GRAY else "#666666")

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
            self.status_var.set("Nothing to scan.")
            self._set_dot(self.DOT_GRAY, "Waiting for input")
            return

        self._set_dot(self.DOT_BLUE, "Scanning...")
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

            display_text = match.text if len(match.text) <= 60 else match.text[:57] + "..."
            self.results_tree.insert("", "end", values=(
                match.pattern_name,
                match.confidence.upper(),
                match.category,
                display_text,
            ))

        count = len(self.matches)
        if count == 0:
            self._set_dot(self.DOT_GREEN, "CLEAR — No PII detected")
            self.status_var.set("No PII detected. Safe to send.")
            self.copy_btn.configure(state="normal")
            self.send_btn.configure(state="normal")
        else:
            high = sum(1 for m in self.matches if m.confidence == "high")
            med = sum(1 for m in self.matches if m.confidence == "medium")
            low = sum(1 for m in self.matches if m.confidence == "low")
            parts = []
            if high:
                parts.append(f"{high} high")
            if med:
                parts.append(f"{med} medium")
            if low:
                parts.append(f"{low} low")
            self._set_dot(self.DOT_RED, f"BLOCKED — {count} PII item(s) found")
            self.status_var.set(f"WARNING: {count} PII item(s) detected ({', '.join(parts)})")
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
        self.text_area.delete("1.0", "end")
        for level in TAG_COLORS:
            self.text_area.tag_remove(f"pii_{level}", "1.0", "end")
        self.text_area.tag_remove("selected_pii", "1.0", "end")
        self.results_tree.delete(*self.results_tree.get_children())
        self.matches = []
        self._set_dot(self.DOT_GRAY, "Waiting for input")
        self.status_var.set("Paste text and press Scan, or just start typing.")
        self.copy_btn.configure(state="disabled")
        self.send_btn.configure(state="disabled")

    def _copy_to_clipboard(self):
        text = self.text_area.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("Copied to clipboard.")

    def _send_to_coco(self):
        text = self.text_area.get("1.0", "end-1c")
        cli = self.config["coco_cli_path"]
        try:
            result = subprocess.run(
                [cli, "send", "--text", text],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                self.status_var.set("Sent to CoCo successfully.")
            else:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                self.status_var.set(f"CoCo CLI failed (copied to clipboard instead). Error: {result.stderr.strip()[:100]}")
        except FileNotFoundError:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_var.set(f"CoCo CLI not found at '{cli}'. Text copied to clipboard instead. Configure path in Settings.")
        except subprocess.TimeoutExpired:
            self.status_var.set("CoCo CLI timed out.")
        except Exception as e:
            self.status_var.set(f"Error: {str(e)[:100]}")

    def _open_settings(self):
        SettingsWindow(self.root, self.config, on_save=self._on_settings_saved)

    def _on_settings_saved(self):
        self.status_var.set("Settings saved. Re-scan to apply changes.")


def main():
    root = tk.Tk()
    app = PiiCheckerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
