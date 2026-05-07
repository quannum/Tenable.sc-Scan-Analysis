import tkinter as tk
from tkinter import filedialog


def prompt_for_inputs():
    root = tk.Tk()
    root.withdraw()

    try:
        scan_json_dir = filedialog.askdirectory(
            title="Select directory to save Scan json files"
        )
        asset_json_dir = filedialog.askdirectory(
            title="Select directory to save Asset json files"
        )
        expected_scope_file = filedialog.askopenfilename(
            title="Select XLSX of expected ranges (e.x. Global IP Address Tracker)",
            filetypes=[("Excel files", "*.xlsx")],
        )
    finally:
        root.destroy()

    return scan_json_dir, asset_json_dir, expected_scope_file
