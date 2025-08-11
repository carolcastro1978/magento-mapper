import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import xml.etree.ElementTree as ET
from collections import defaultdict
import json
import csv
import re

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
        self.vendor_entry.pack(anchor="w", padx=10, pady=5)

        self.order_mode = tk.StringVar(master=self.root, value="asc_name")
        ttk.Label(self.root, text="Order by:").pack(anchor="w", padx=10)
        order_options = ["asc_name", "desc_name", "asc_count", "desc_count"]
        self.order_menu = ttk.Combobox(self.root, textvariable=self.order_mode, values=order_options, state="readonly", width=20)
        self.order_menu.pack(anchor="w", padx=10, pady=(0, 10))
        self.order_menu.bind("<<ComboboxSelected>>", lambda e: self.display_results())

        # Quick text filter (applies to interface, class, module, and area)
        ttk.Label(self.root, text="Filter (contains):").pack(anchor="w", padx=10)
        self.quick_filter = tk.StringVar(master=self.root, value="")
        self.quick_filter_entry = ttk.Entry(self.root, width=80, textvariable=self.quick_filter)
        self.quick_filter_entry.pack(anchor="w", padx=10, pady=(0, 10))
        self.quick_filter_entry.bind("<KeyRelease>", lambda e: self.display_results())

        # Filter mode and case sensitivity
        ttk.Label(self.root, text="Filter mode:").pack(anchor="w", padx=10)
        self.filter_mode = tk.StringVar(master=self.root, value="contains")
        fm_frame = ttk.Frame(self.root)
        fm_frame.pack(anchor="w", padx=10, pady=(0, 6))
        for mode_option in ["contains", "regex", "startswith", "endswith", "equals"]:
            ttk.Radiobutton(fm_frame, text=mode_option, value=mode_option,
                            variable=self.filter_mode, command=self.display_results).pack(side="left", padx=(0, 10))
        self.filter_case = tk.IntVar(master=self.root, value=0)
        ttk.Checkbutton(self.root, text="Case sensitive", variable=self.filter_case).pack(anchor="w", padx=20)

        # Area filters (global / frontend / adminhtml)
        ttk.Label(self.root, text="Area Filters:").pack(anchor="w", padx=10, pady=(10, 0))
        self.area_vars = {
            "global": tk.IntVar(master=self.root, value=1),
            "frontend": tk.IntVar(master=self.root, value=1),
            "adminhtml": tk.IntVar(master=self.root, value=1),
        }
        for area_key in ("global", "frontend", "adminhtml"):
            ttk.Checkbutton(self.root, text=area_key, variable=self.area_vars[area_key]).pack(anchor="w", padx=20)
        # Option to include ANY etc/* area (ignore area filter)
        self.include_all_areas = tk.IntVar(master=self.root, value=1)
        ttk.Checkbutton(self.root, text="Include ANY etc/* area (ignore area filter)", variable=self.include_all_areas).pack(anchor="w", padx=20)

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
        # Gather selected areas; when include_all_areas is ON, this will be ignored
        selected_areas = []
        if hasattr(self, "area_vars"):
            selected_areas = [k for k, v in self.area_vars.items() if v.get() == 1]
        include_all = hasattr(self, "include_all_areas") and self.include_all_areas.get() == 1
        all_preferences = defaultdict(lambda: defaultdict(list))  # {interface: {area: [dicts]}}

        for file in self.find_di_files():
            # Determine area from path. Default to "global" if di.xml is directly under etc
            area = "global"
            m = re.search(r"/etc/([^/]+)/", file.replace("\\", "/"))
            if m:
                area = m.group(1)
            # Respect area filters only when "include all" is OFF
            if not include_all and selected_areas:
                if area not in selected_areas:
                    continue

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
        order_mode = self.order_mode.get()
        needle_raw = (self.quick_filter.get() or "").strip()
        mode = getattr(self, "filter_mode", tk.StringVar(value="contains")).get()
        case_sensitive = getattr(self, "filter_case", tk.IntVar(value=0)).get() == 1
        # Prepare helpers for matching
        if not case_sensitive:
            needle = needle_raw.lower()
        else:
            needle = needle_raw
        pattern = None
        invalid_regex = False
        if mode == "regex" and needle_raw:
            try:
                flags = 0 if case_sensitive else re.IGNORECASE
                pattern = re.compile(needle_raw, flags)
            except re.error:
                invalid_regex = True

        def match_text(haystack):
            if not needle_raw:
                return True
            if mode == "regex":
                if invalid_regex:
                    return False
                return bool(pattern.search(haystack))
            if not case_sensitive:
                hay = haystack.lower()
                ned = needle
            else:
                hay = haystack
                ned = needle
            if mode == "contains":
                return ned in hay
            if mode == "startswith":
                return hay.startswith(ned)
            if mode == "endswith":
                return hay.endswith(ned)
            if mode == "equals":
                return hay == ned
            # Fallback to contains
            return ned in hay

        def entry_matches(interface_name, area_name, entry):
            if not needle_raw:
                return True
            if match_text(interface_name):
                return True
            if match_text(entry.get("class", "")):
                return True
            if match_text(entry.get("module", "")):
                return True
            if match_text(area_name or ""):
                return True
            return False

        filtered_results = {}
        for interface, areas in self.results.items():
            kept_areas = {}
            for area, entries in areas.items():
                kept_entries = [e for e in entries if entry_matches(interface, area, e)]
                if kept_entries:
                    kept_areas[area] = kept_entries
            if kept_areas:
                filtered_results[interface] = kept_areas

        if order_mode == "asc_name":
            sorted_interfaces = sorted(filtered_results.items())
        elif order_mode == "desc_name":
            sorted_interfaces = sorted(filtered_results.items(), reverse=True)
        elif order_mode in ("asc_count", "desc_count"):
            reverse = order_mode == "desc_count"
            sorted_interfaces = sorted(
                filtered_results.items(),
                key=lambda item: sum(len(entries) for entries in item[1].values()),
                reverse=reverse
            )
        else:
            sorted_interfaces = filtered_results.items()

        # Show feedback if regex is invalid
        if mode == "regex" and invalid_regex:
            self.loading_label.config(text="⚠️ Invalid regex — showing no matches")
        else:
            self.loading_label.config(text="")

        for interface, areas in sorted_interfaces:
            count = sum(len(entries) for entries in areas.values())
            interface_label = f"{interface} ({count})"
            interface_node = self.tree.insert("", "end", text=interface_label, values=("", ""))
            for area, entries in sorted(areas.items()):
                # Create an area node with count, then list entries under it
                area_label = f"↳ {area} ({len(entries)})"
                area_node = self.tree.insert(interface_node, "end", text=area_label, values=("", ""))
                for entry in entries:
                    self.tree.insert(area_node, "end", text="└", values=(entry["class"], entry["module"]))

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