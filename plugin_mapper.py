import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import xml.etree.ElementTree as ET
from collections import defaultdict
import json
import csv

class PluginMapperApp:
    def __init__(self, root, base_path):
        self.root = root
        self.root.title("Magento 2 Plugin Mapper")
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

        # Area filters (global / frontend / adminhtml)
        ttk.Label(self.root, text="Area Filters:").pack(anchor="w", padx=10, pady=(10, 0))
        self.area_vars = {
            "global": tk.IntVar(master=self.root, value=1),
            "frontend": tk.IntVar(master=self.root, value=1),
            "adminhtml": tk.IntVar(master=self.root, value=1),
        }
        for area_key in ("global", "frontend", "adminhtml"):
            ttk.Checkbutton(self.root, text=area_key, variable=self.area_vars[area_key]).pack(anchor="w", padx=20)

        # Sort options
        self.sort_mode = tk.StringVar(master=self.root, value="asc_name")
        ttk.Label(self.root, text="Sort by:").pack(anchor="w", padx=10)
        sort_options = ["asc_name", "desc_name", "asc_count", "desc_count"]
        self.sort_menu = ttk.Combobox(self.root, textvariable=self.sort_mode, values=sort_options, state="readonly", width=20)
        self.sort_menu.pack(anchor="w", padx=10, pady=(0, 10))
        self.sort_menu.bind("<<ComboboxSelected>>", lambda e: self.display_results())
    def get_selected_areas(self):
        return [k for k, v in self.area_vars.items() if v.get() == 1]

        # Scan button
        ttk.Button(self.root, text="Scan Plugins", command=self.scan).pack(pady=10)

        self.loading_label = ttk.Label(self.root, text="", font=("Arial", 10, "italic"))
        self.loading_label.pack(pady=(0, 10))

        # Table container frame (use grid inside this frame)
        table_frame = ttk.Frame(self.root)
        table_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # Configure grid on the frame to allow the treeview to expand
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Tree output inside the frame
        self.tree = ttk.Treeview(table_frame, show="headings")
        self.tree["columns"] = ("target", "plugin", "module")
        self.tree["displaycolumns"] = ("target", "plugin", "module")
        for col, label, width in (
            ("target", "Target Class (type)", 400),
            ("plugin", "Plugin Class (type)", 380),
            ("module", "Module", 200),
        ):
            self.tree.heading(col, text=label, anchor="w")
            self.tree.column(col, width=width, minwidth=80, anchor="w", stretch=True)
        self.tree.grid(row=0, column=0, sticky="nsew", ipadx=1, ipady=1)

        # Scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        hsb.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Export buttons
        ttk.Button(self.root, text="Export to JSON", command=self.export_json).pack(side="left", padx=20, pady=10)
        ttk.Button(self.root, text="Export to CSV", command=self.export_csv).pack(side="right", padx=20, pady=10)

        # Back button
        ttk.Button(self.root, text="⬅️ Back", command=self.go_back).pack(pady=5)

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

    def parse_plugins(self, file_path):
        plugins = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Plugins inside <type name="..."> ... </type>
            for t in root.findall('.//type'):
                target = t.attrib.get('name')
                if not target:
                    continue
                for p in t.findall('plugin'):
                    name = p.attrib.get('name')
                    plugin_class = p.attrib.get('type')  # Magento uses `type` for plugin class
                    if target and name and plugin_class:
                        plugins.append((target, name, plugin_class))

            # Plugins inside <virtualType name="..."> ... </virtualType>
            for vt in root.findall('.//virtualType'):
                target = vt.attrib.get('name')
                if not target:
                    continue
                for p in vt.findall('plugin'):
                    name = p.attrib.get('name')
                    plugin_class = p.attrib.get('type')
                    if target and name and plugin_class:
                        plugins.append((target, name, plugin_class))
        except ET.ParseError as e:
            print(f"⚠️  Failed to parse {file_path}: {e}")
        return plugins

    def scan(self):
        self.loading_label.config(text="🔄 Scanning plugins...")
        self.root.update()

        vendor_filters = self.get_vendor_filters()
        selected_areas = self.get_selected_areas()
        all_plugins = defaultdict(lambda: defaultdict(list))  # {type: {area: [dict]}}

        for file in self.find_di_files():
            if "/etc/frontend/" in file:
                area = "frontend"
            elif "/etc/adminhtml/" in file:
                area = "adminhtml"
            elif "/etc/" in file:
                area = "global"
            else:
                area = "unknown"

            if area not in selected_areas:
                continue

            module_path = file.split("/etc/")[0]
            vendor_module_parts = module_path.strip("/").split("/")[-2:]
            module_name = "_".join(vendor_module_parts) if len(vendor_module_parts) == 2 else "Unknown"

            for target, name, plugin_class in self.parse_plugins(file):
                if "all" in vendor_filters or any(plugin_class.startswith(v + "\\") for v in vendor_filters):
                    all_plugins[target][area].append({
                        "name": name,
                        "class": plugin_class,
                        "module": module_name
                    })

        self.results = {}
        for target, area_data in all_plugins.items():
            self.results[target] = {}
            for area, entries in area_data.items():
                seen = set()
                deduped = []
                for entry in entries:
                    key = (entry["class"], entry["name"])
                    if key not in seen:
                        seen.add(key)
                        deduped.append(entry)
                self.results[target][area] = sorted(deduped, key=lambda x: x["class"])

        self.loading_label.config(text="")
        self.display_results()

    def display_results(self):
        self.tree.delete(*self.tree.get_children())
        sort_mode = self.sort_mode.get()

        if sort_mode == "asc_name":
            sorted_targets = sorted(self.results.items())
        elif sort_mode == "desc_name":
            sorted_targets = sorted(self.results.items(), reverse=True)
        elif sort_mode in ("asc_count", "desc_count"):
            reverse = sort_mode == "desc_count"
            sorted_targets = sorted(
                self.results.items(),
                key=lambda item: sum(len(entries) for entries in item[1].values()),
                reverse=reverse
            )
        else:
            sorted_targets = self.results.items()

        for target, areas in sorted_targets:
            count = sum(len(entries) for entries in areas.values())
            label = f"{target} ({count})"
            target_node = self.tree.insert("", "end", values=(label, "", ""))
            for area, entries in sorted(areas.items()):
                for entry in entries:
                    self.tree.insert(target_node, "end", values=(f"↳ {area}", entry["class"], entry["module"]))

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
                writer.writerow(["Target Class", "Area", "Plugin Class", "Plugin Name", "Module"])
                for target, areas in self.results.items():
                    for area, entries in areas.items():
                        for entry in entries:
                            writer.writerow([target, area, entry["class"], entry["name"], entry["module"]])
            messagebox.showinfo("Exported", f"Exported to {path}")