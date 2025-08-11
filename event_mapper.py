import os
import xml.etree.ElementTree as ET
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import csv

class MagentoEventScannerApp:
    def __init__(self, root, base_path):
        self.root = root
        self.root.title("Magento 2 Event Observer Scanner")
        self.root.geometry("1000x700")
        self.base_path = base_path
        self.results = {}

        self.init_ui()

    def init_ui(self):
        # Area filters (checkboxes)
        self.area_vars = {
            "global": tk.IntVar(master=self.root, value=1),
            "frontend": tk.IntVar(master=self.root, value=1),
            "adminhtml": tk.IntVar(master=self.root, value=1)
        }
        ttk.Label(self.root, text="Area Filters:").pack(anchor="w", padx=10, pady=(10, 0))
        for area in self.area_vars:
            cb = tk.Checkbutton(self.root, text=area, variable=self.area_vars[area])
            cb.pack(anchor="w", padx=20)

        # Vendor filter
        ttk.Label(self.root, text="Vendor Filter (comma-separated):").pack(anchor="w", padx=10, pady=(10, 0))
        self.vendor_entry = tk.Entry(self.root, width=80)
        self.vendor_entry.insert(0, "all")
        self.vendor_entry.pack(padx=10, pady=5)

        # Event filter
        ttk.Label(self.root, text="Event Filter (comma-separated, optional):").pack(anchor="w", padx=10, pady=(10, 0))
        self.event_entry = tk.Entry(self.root, width=80)
        self.event_entry.insert(0, "all")
        self.event_entry.pack(padx=10, pady=5)

        # Sorting dropdown
        self.sort_mode = tk.StringVar(master=self.root, value="asc_name")
        ttk.Label(self.root, text="Sort by:").pack(anchor="w", padx=10)
        sort_options = ["asc_name", "desc_name", "asc_count", "desc_count"]
        self.sort_menu = ttk.Combobox(self.root, textvariable=self.sort_mode, values=sort_options, state="readonly", width=20)
        self.sort_menu.pack(anchor="w", padx=10, pady=(0, 10))
        self.sort_menu.bind("<<ComboboxSelected>>", lambda e: self.display_results())

        # Scan button
        ttk.Button(self.root, text="Scan Magento Events", command=self.scan).pack(pady=10)

        self.loading_label = ttk.Label(self.root, text="", font=("Arial", 10, "italic"))
        self.loading_label.pack(pady=(0, 10))

        # Tree output
        self.tree = ttk.Treeview(self.root)
        self.tree["columns"] = ("observers", "module")
        self.tree.heading("#0", text="Event")
        self.tree.heading("observers", text="Observer Class")
        self.tree.heading("module", text="Module")
        self.tree.pack(expand=True, fill="both", padx=10, pady=10)

        # Export buttons
        ttk.Button(self.root, text="Export to JSON", command=self.export_json).pack(side="left", padx=20, pady=10)
        ttk.Button(self.root, text="Export to CSV", command=self.export_csv).pack(side="right", padx=20, pady=10)

        # Back button at the bottom
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

    def get_selected_areas(self):
        return [area for area, var in self.area_vars.items() if var.get() == 1]

    def get_vendor_filters(self):
        raw = self.vendor_entry.get().strip()
        if raw.lower() == "all" or raw == "":
            return ["all"]
        return [v.strip() for v in raw.split(",") if v.strip()]

    def get_event_filters(self):
        raw = self.event_entry.get().strip()
        if raw.lower() == "all" or raw == "":
            return ["all"]
        return [e.strip() for e in raw.split(",") if e.strip()]

    def find_events_xml_files(self, area_filter):
        events_files = []
        for root, _, files in os.walk(self.base_path):
            for file in files:
                if file == "events.xml":
                    path = os.path.join(root, file)
                    if "etc" not in path:
                        continue
                    if any(f"/{area}/" in path or path.endswith(f"/{area}/events.xml") for area in area_filter):
                        events_files.append(path)
                    elif "etc/events.xml" in path and "global" in area_filter:
                        events_files.append(path)
        return events_files

    def parse_events_file(self, file_path):
        events = defaultdict(list)
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            for event in root.findall("event"):
                event_name = event.attrib.get("name")
                for observer in event.findall("observer"):
                    instance = observer.attrib.get("instance")
                    if event_name and instance:
                        events[event_name].append(instance)
        except ET.ParseError as e:
            print(f"⚠️  Failed to parse {file_path}: {e}")
        return events

    def scan(self):
        area_filter = self.get_selected_areas()
        vendor_filter = self.get_vendor_filters()
        event_filter = self.get_event_filters()

        self.loading_label.config(text="🔄 Scanning events...")
        self.root.update()

        all_events = defaultdict(lambda: defaultdict(list))  # {event: {area: [dicts]}}

        event_files = self.find_events_xml_files(area_filter)
        for file in event_files:
            event_data = self.parse_events_file(file)
            area = 'global' if '/etc/events.xml' in file else (
                'frontend' if '/etc/frontend/' in file else (
                    'adminhtml' if '/etc/adminhtml/' in file else 'other'
                )
            )
            module_path = file.split("/etc/")[0]
            vendor_module_parts = module_path.strip("/").split("/")[-2:]
            module_name = "_".join(vendor_module_parts) if len(vendor_module_parts) == 2 else "Unknown"
            for event, observers in event_data.items():
                if "all" not in event_filter and event not in event_filter:
                    continue
                for observer in observers:
                    if "all" in vendor_filter or any(observer.startswith(v + "\\") for v in vendor_filter):
                        all_events[event][area].append({
                            "class": observer,
                            "module": module_name
                        })

        self.results = {}
        for event, area_data in all_events.items():
            self.results[event] = {}
            for area, items in area_data.items():
                seen = set()
                deduped = []
                for entry in items:
                    key = (entry["class"], entry["module"])
                    if key not in seen:
                        seen.add(key)
                        deduped.append(entry)
                self.results[event][area] = sorted(deduped, key=lambda x: x["class"])

        self.loading_label.config(text="")

        self.display_results()

    def display_results(self):
        self.tree.delete(*self.tree.get_children())
        sort_mode = self.sort_mode.get()

        if sort_mode == "asc_name":
            sorted_events = sorted(self.results.items())
        elif sort_mode == "desc_name":
            sorted_events = sorted(self.results.items(), reverse=True)
        elif sort_mode in ("asc_count", "desc_count"):
            reverse = sort_mode == "desc_count"
            sorted_events = sorted(
                self.results.items(),
                key=lambda item: sum(len(entries) for entries in item[1].values()),
                reverse=reverse
            )
        else:
            sorted_events = self.results.items()

        for event, areas in sorted_events:
            count = sum(len(entries) for entries in areas.values())
            event_label = f"{event} ({count})"
            event_node = self.tree.insert("", "end", text=event_label, values=(""))
            for area, entries in sorted(areas.items()):
                for entry in entries:
                    self.tree.insert(event_node, "end", text=f"↳ {area}", values=(entry["class"], entry["module"]))

    def export_json(self):
        if not self.results:
            messagebox.showwarning("No Data", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[["JSON Files", "*.json"]])
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
                writer.writerow(["Event", "Area", "Observer Class", "Module"])
                for event, areas in self.results.items():
                    for area, entries in areas.items():
                        for entry in entries:
                            writer.writerow([event, area, entry["class"], entry["module"]])
            messagebox.showinfo("Exported", f"Exported to {path}")