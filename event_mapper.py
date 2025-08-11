import os
import xml.etree.ElementTree as ET
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import csv
import re
from difflib import SequenceMatcher


class MagentoEventScannerApp:
    def __init__(self, root, base_path):
        self.root = root
        self.root.title("Magento 2 Event Observer Scanner")
        self.root.geometry("1000x750")  # Slightly taller for new search options
        self.base_path = base_path
        self.results = {}
        self.all_events_data = {}  # Store all events for filtering

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

        # Option to include ANY area under etc (e.g., crontab, webapi_rest, graphql, etc.)
        self.include_all_areas = tk.IntVar(master=self.root, value=1)
        cb_all = tk.Checkbutton(self.root, text="Include ANY etc/* area (ignore area filter)", variable=self.include_all_areas)
        cb_all.pack(anchor="w", padx=20)

        # Vendor filter
        ttk.Label(self.root, text="Vendor Filter (comma-separated):").pack(anchor="w", padx=10, pady=(10, 0))
        self.vendor_entry = tk.Entry(self.root, width=80)
        self.vendor_entry.insert(0, "all")
        self.vendor_entry.pack(anchor="w", padx=10, pady=5)

        # Event filter section with search type
        event_frame = tk.Frame(self.root)
        event_frame.pack(anchor="w", padx=10, pady=(10, 0), fill="x")

        ttk.Label(event_frame, text="Event Filter:").pack(anchor="w")

        # Search type selection
        search_frame = tk.Frame(event_frame)
        search_frame.pack(anchor="w", pady=(5, 0))

        ttk.Label(search_frame, text="Search Type:").pack(side="left")

        self.search_type = tk.StringVar(master=self.root, value="partial")
        search_types = [
            ("Partial Match", "partial"),
            ("Exact Match", "exact"),
            ("Starts With", "starts_with"),
            ("Fuzzy Match", "fuzzy"),
            ("Regex Pattern", "regex")
        ]

        for text, value in search_types:
            rb = tk.Radiobutton(search_frame, text=text, variable=self.search_type, value=value)
            rb.pack(side="left", padx=(10, 0))

        # Event search entry
        search_entry_frame = tk.Frame(event_frame)
        search_entry_frame.pack(anchor="w", pady=(5, 0), fill="x")

        self.event_entry = tk.Entry(search_entry_frame, width=60)
        self.event_entry.insert(0, "all")
        self.event_entry.pack(side="left", padx=(0, 10))

        # Help text for search types
        help_frame = tk.Frame(event_frame)
        help_frame.pack(anchor="w", pady=(5, 0))
        help_text = (
            "• Partial: Contains the search term (e.g., 'customer' finds 'customer_login')\n"
            "• Exact: Exact match only\n"
            "• Starts With: Event name starts with the term (good for autocomplete)\n"
            "• Fuzzy: Handles typos and similar names\n"
            "• Regex: Use regular expressions for advanced patterns"
        )
        help_label = tk.Label(help_frame, text=help_text, font=("Arial", 8), fg="gray", justify="left")
        help_label.pack(anchor="w")

        # Sorting dropdown
        self.sort_mode = tk.StringVar(master=self.root, value="asc_name")
        ttk.Label(self.root, text="Sort by:").pack(anchor="w", padx=10)
        sort_options = ["asc_name", "desc_name", "asc_count", "desc_count"]
        self.sort_menu = ttk.Combobox(self.root, textvariable=self.sort_mode, values=sort_options, state="readonly",
                                      width=20)
        self.sort_menu.pack(anchor="w", padx=10, pady=(0, 10))
        self.sort_menu.bind("<<ComboboxSelected>>", lambda e: self.display_results())

        # Scan button
        ttk.Button(self.root, text="Scan Magento Events", command=self.scan).pack(pady=10)

        self.loading_label = ttk.Label(self.root, text="", font=("Arial", 10, "italic"))
        self.loading_label.pack(pady=(0, 10))

        # Results counter
        self.results_label = ttk.Label(self.root, text="", font=("Arial", 9))
        self.results_label.pack(pady=(0, 5))

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

    def matches_event_filter(self, event_name, search_terms, search_type):
        """
        Check if an event name matches the search criteria based on the search type.
        """
        if search_terms == ["all"]:
            return True

        for term in search_terms:
            if self._single_term_matches(event_name, term, search_type):
                return True
        return False

    def _single_term_matches(self, event_name, search_term, search_type):
        """
        Check if a single search term matches the event name based on search type.
        """
        if search_type == "exact":
            return event_name.lower() == search_term.lower()

        elif search_type == "partial":
            return search_term.lower() in event_name.lower()

        elif search_type == "starts_with":
            return event_name.lower().startswith(search_term.lower())

        elif search_type == "fuzzy":
            # Use fuzzy matching with a threshold
            similarity = SequenceMatcher(None, search_term.lower(), event_name.lower()).ratio()
            return similarity >= 0.6  # 60% similarity threshold

        elif search_type == "regex":
            try:
                pattern = re.compile(search_term, re.IGNORECASE)
                return bool(pattern.search(event_name))
            except re.error:
                # If regex is invalid, fall back to partial matching
                return search_term.lower() in event_name.lower()

        return False

    def find_events_xml_files(self, area_filter):
        events_files = []
        for root, _, files in os.walk(self.base_path):
            for file in files:
                if file != "events.xml":
                    continue
                path = os.path.join(root, file)
                # Only consider files under an etc directory
                if "etc" not in path:
                    continue

                # If the "include all areas" toggle is on, take any events.xml under etc/*
                if hasattr(self, "include_all_areas") and self.include_all_areas.get() == 1:
                    events_files.append(path)
                    continue

                # Otherwise, respect selected areas (global, frontend, adminhtml)
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

        self.loading_label.config(text="🔄 Scanning events...")
        self.root.update()

        # Collect ALL events first, before filtering
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
                for observer in observers:
                    if "all" in vendor_filter or any(observer.startswith(v + "\\") for v in vendor_filter):
                        all_events[event][area].append({
                            "class": observer,
                            "module": module_name
                        })

        # Store all events for filtering
        self.all_events_data = {}
        for event, area_data in all_events.items():
            self.all_events_data[event] = {}
            for area, items in area_data.items():
                seen = set()
                deduped = []
                for entry in items:
                    key = (entry["class"], entry["module"])
                    if key not in seen:
                        seen.add(key)
                        deduped.append(entry)
                self.all_events_data[event][area] = sorted(deduped, key=lambda x: x["class"])

        self.loading_label.config(text="")

        # Apply event filtering and display
        self.filter_events_live()

    def filter_events_live(self):
        """
        Filter the events based on current search criteria without re-scanning.
        """
        if not self.all_events_data:
            return

        event_filter = self.get_event_filters()
        search_type = self.search_type.get()

        # Filter events based on search criteria
        self.results = {}
        for event, area_data in self.all_events_data.items():
            if self.matches_event_filter(event, event_filter, search_type):
                self.results[event] = area_data

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

        total_events = len(self.results)
        total_observers = sum(sum(len(entries) for entries in areas.values()) for areas in self.results.values())

        # Update results counter
        self.results_label.config(text=f"Found {total_events} events with {total_observers} observers")

        for event, areas in sorted_events:
            count = sum(len(entries) for entries in areas.values())
            event_label = f"{event} ({count})"
            event_node = self.tree.insert("", "end", text=event_label, values=(""))
            for area, entries in sorted(areas.items()):
                for entry in entries:
                    self.tree.insert(event_node, "end", text=f"↳ {area}", values=(entry["class"], entry["module"]))

    def get_event_suggestions(self, partial_term, max_suggestions=10):
        """
        Get event name suggestions for autocomplete functionality.
        """
        if not self.all_events_data or len(partial_term) < 2:
            return []

        suggestions = []
        partial_lower = partial_term.lower()

        for event_name in self.all_events_data.keys():
            if event_name.lower().startswith(partial_lower):
                suggestions.append(event_name)
            elif len(suggestions) < max_suggestions and partial_lower in event_name.lower():
                suggestions.append(event_name)

        return sorted(suggestions)[:max_suggestions]

    def export_json(self):
        if not self.results:
            messagebox.showwarning("No Data", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[["JSON Files", "*.json"]])
        if path:
            # Include search metadata in export
            export_data = {
                "search_criteria": {
                    "event_filter": self.event_entry.get(),
                    "search_type": self.search_type.get(),
                    "vendor_filter": self.vendor_entry.get(),
                    "areas": [area for area, var in self.area_vars.items() if var.get()]
                },
                "results": self.results
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)
            messagebox.showinfo("Exported", f"Exported to {path}")

    def export_csv(self):
        if not self.results:
            messagebox.showwarning("No Data", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if path:
            with open(path, "w", encoding="utf-8", newline='') as f:
                writer = csv.writer(f)
                # Include search criteria in CSV header
                writer.writerow(
                    [f"# Search: {self.event_entry.get()}, Type: {self.search_type.get()}, Vendor: {self.vendor_entry.get()}"])
                writer.writerow(["Event", "Area", "Observer Class", "Module"])
                for event, areas in self.results.items():
                    for area, entries in areas.items():
                        for entry in entries:
                            writer.writerow([event, area, entry["class"], entry["module"]])
            messagebox.showinfo("Exported", f"Exported to {path}")


# Example of how to use the enhanced search functionality
if __name__ == "__main__":
    # This would normally be called from your main application
    root = tk.Tk()
    app = MagentoEventScannerApp(root, "/path/to/magento/root")
    root.mainloop()