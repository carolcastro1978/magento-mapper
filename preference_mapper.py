import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import xml.etree.ElementTree as ET
from collections import defaultdict
import json
import csv

class PreferenceMapperApp:
    def __init__(self, root, base_path):
        self.root = root
        self.root.title("Magento 2 Preference Mapper")
        self.root.geometry("1000x700")
        self.base_path = base_path
        self.results = {}

        self.init_ui()

    def init_ui(self):
        # Vendor filter input
        ttk.Label(self.root, text="Vendor Filter (comma-separated):").pack(anchor="w", padx=10, pady=(10, 0))
        self.vendor_entry = ttk.Entry(self.root, width=80)
        self.vendor_entry.insert(0, "all")
        self.vendor_entry.pack(padx=10, pady=5)

        self.sort_mode = tk.StringVar(master=self.root, value="asc_name")
        ttk.Label(self.root, text="Sort by:").pack(anchor="w", padx=10)
        sort_options = ["asc_name", "desc_name", "asc_count", "desc_count"]
        self.sort_menu = ttk.Combobox(self.root, textvariable=self.sort_mode, values=sort_options, state="readonly", width=20)
        self.sort_menu.pack(anchor="w", padx=10, pady=(0, 10))
        self.sort_menu.bind("<<ComboboxSelected>>", lambda e: self.display_results())

        # Scan button
        ttk.Button(self.root, text="Scan Preferences", command=self.scan).pack(pady=10)

        self.loading_label = ttk.Label(self.root, text="", font=("Arial", 10, "italic"))
        self.loading_label.pack(pady=(0, 10))

        # Tree output
        self.tree = ttk.Treeview(self.root)
        self.tree["columns"] = ("implementation", "module")
        self.tree.heading("#0", text="Interface (for)")
        self.tree.heading("implementation", text="Preference (type)")
        self.tree.heading("module", text="Module")
        self.tree.pack(expand=True, fill="both", padx=10, pady=10)

        # Export buttons
        ttk.Button(self.root, text="Export to JSON", command=self.export_json).pack(side="left", padx=20, pady=10)
        ttk.Button(self.root, text="Export to CSV", command=self.export_csv).pack(side="right", padx=20, pady=10)

        # Back button
        ttk.Button(self.root, text="⬅️ Back", command=self.go_back).pack(pady=5)

    def get_vendor_filters(self):
        raw = self.vendor_entry.get().strip()
        if raw.lower() == "all" or raw == "":
            return ["all"]
        return [v.strip() for v in raw.split(",") if v.strip()]

    def find_di_files(self):
        di_files = []
        for root, _, files in os.walk(self.base_path):
            for file in files:
                if file == "di.xml":
                    di_files.append(os.path.join(root, file))
        return di_files

    def parse_di_file(self, file_path):
        preferences = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            for pref in root.findall("preference"):
                interface = pref.attrib.get("for")
                implementation = pref.attrib.get("type")
                if interface and implementation:
                    preferences.append((interface, implementation))
        except ET.ParseError as e:
            print(f"⚠️  Failed to parse {file_path}: {e}")
        return preferences

    def scan(self):
        self.loading_label.config(text="🔄 Scanning preferences...")
        self.root.update()

        vendor_filters = self.get_vendor_filters()
        all_preferences = defaultdict(lambda: defaultdict(list))  # {interface: {area: [dicts]}}

        for file in self.find_di_files():
            if "/frontend/" in file:
                area = "frontend"
            elif "/adminhtml/" in file:
                area = "adminhtml"
            elif "/etc/" in file:
                area = "global"
            else:
                area = "unknown"

            module_path = file.split("/etc/")[0]
            vendor_module_parts = module_path.strip("/").split("/")[-2:]
            module_name = "_".join(vendor_module_parts) if len(vendor_module_parts) == 2 else "Unknown"

            prefs = self.parse_di_file(file)
            for interface, implementation in prefs:
                if "all" in vendor_filters or any(implementation.startswith(v + "\\") for v in vendor_filters):
                    all_preferences[interface][area].append({
                        "class": implementation,
                        "module": module_name
                    })

        self.results = {}
        for interface, area_data in all_preferences.items():
            self.results[interface] = {}
            for area, entries in area_data.items():
                seen = set()
                deduped = []
                for entry in entries:
                    key = (entry["class"], entry["module"])
                    if key not in seen:
                        seen.add(key)
                        deduped.append(entry)
                self.results[interface][area] = sorted(deduped, key=lambda x: x["class"])

        self.loading_label.config(text="")

        self.display_results()

    def display_results(self):
        self.tree.delete(*self.tree.get_children())
        sort_mode = self.sort_mode.get()

        if sort_mode == "asc_name":
            sorted_interfaces = sorted(self.results.items())
        elif sort_mode == "desc_name":
            sorted_interfaces = sorted(self.results.items(), reverse=True)
        elif sort_mode in ("asc_count", "desc_count"):
            reverse = sort_mode == "desc_count"
            sorted_interfaces = sorted(
                self.results.items(),
                key=lambda item: sum(len(entries) for entries in item[1].values()),
                reverse=reverse
            )
        else:
            sorted_interfaces = self.results.items()

        for interface, areas in sorted_interfaces:
            count = sum(len(entries) for entries in areas.values())
            interface_label = f"{interface} ({count})"
            interface_node = self.tree.insert("", "end", text=interface_label, values=("", ""))
            for area, entries in sorted(areas.items()):
                for entry in entries:
                    self.tree.insert(interface_node, "end", text=f"↳ {area}", values=(entry["class"], entry["module"]))

    def export_json(self):
        if not self.results:
            messagebox.showwarning("No Data", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2)
            messagebox.showinfo("Exported", f"Exported to {path}")

    def export_csv(self):
        if not self.results:
            messagebox.showwarning("No Data", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if path:
            with open(path, "w", encoding="utf-8", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Interface", "Area", "Class", "Module"])
                for interface, areas in self.results.items():
                    for area, entries in areas.items():
                        for entry in entries:
                            writer.writerow([interface, area, entry["class"], entry["module"]])
            messagebox.showinfo("Exported", f"Exported to {path}")

    def go_back(self):
        # Close this window and show the main launcher again
        try:
            parent = self.root.master
        except Exception:
            parent = None
        self.root.destroy()
        if parent is not None:
            try:
                parent.deiconify()
            except Exception:
                pass