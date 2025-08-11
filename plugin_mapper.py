import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import xml.etree.ElementTree as ET
from collections import defaultdict
import json
import csv
import re
from difflib import SequenceMatcher


class PluginMapperApp:
    def __init__(self, root, base_path):
        self.root = root
        self.root.title("Magento 2 Plugin Mapper")
        self.root.geometry("1000x750")  # Slightly taller for new search options
        self.base_path = base_path
        self.results = {}
        self.all_plugins_data = {}  # Store all plugins for filtering

        self.init_ui()

    def init_ui(self):
        # Vendor filter input
        ttk.Label(self.root, text="Vendor Filter (comma-separated):").pack(anchor="w", padx=10, pady=(10, 0))
        self.vendor_entry = ttk.Entry(self.root, width=80)
        self.vendor_entry.insert(0, "all")
        self.vendor_entry.pack(anchor="w", padx=10, pady=5)

        # Plugin filter section with search type
        plugin_frame = tk.Frame(self.root)
        plugin_frame.pack(anchor="w", padx=10, pady=(10, 0), fill="x")

        ttk.Label(plugin_frame, text="Plugin/Target Class Filter:").pack(anchor="w")

        # Search type selection
        search_frame = tk.Frame(plugin_frame)
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

        # Plugin search entry
        search_entry_frame = tk.Frame(plugin_frame)
        search_entry_frame.pack(anchor="w", pady=(5, 0), fill="x")

        self.plugin_entry = tk.Entry(search_entry_frame, width=60)
        self.plugin_entry.insert(0, "all")
        self.plugin_entry.pack(side="left", padx=(0, 10))

        # Help text for search types
        help_frame = tk.Frame(plugin_frame)
        help_frame.pack(anchor="w", pady=(5, 0))
        help_text = (
            "• Partial: Contains the search term (e.g., 'Product' finds 'ProductRepository')\n"
            "• Exact: Exact match only\n"
            "• Starts With: Class name starts with the term (good for autocomplete)\n"
            "• Fuzzy: Handles typos and similar names\n"
            "• Regex: Use regular expressions for advanced patterns"
        )
        help_label = tk.Label(help_frame, text=help_text, font=("Arial", 8), fg="gray", justify="left")
        help_label.pack(anchor="w")

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

        # Sort options
        self.sort_mode = tk.StringVar(master=self.root, value="asc_name")
        ttk.Label(self.root, text="Sort by:").pack(anchor="w", padx=10)
        sort_options = ["asc_name", "desc_name", "asc_count", "desc_count"]
        self.sort_menu = ttk.Combobox(self.root, textvariable=self.sort_mode, values=sort_options, state="readonly",
                                      width=20)
        self.sort_menu.pack(anchor="w", padx=10, pady=(0, 10))
        self.sort_menu.bind("<<ComboboxSelected>>", lambda e: self.display_results())

        # Scan button
        ttk.Button(self.root, text="Scan Plugins", command=self.scan).pack(pady=10)

        self.loading_label = ttk.Label(self.root, text="", font=("Arial", 10, "italic"))
        self.loading_label.pack(pady=(0, 10))

        # Results counter
        self.results_label = ttk.Label(self.root, text="", font=("Arial", 9))
        self.results_label.pack(pady=(0, 5))

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

    def get_selected_areas(self):
        return [k for k, v in self.area_vars.items() if v.get() == 1]

    def get_vendor_filters(self):
        raw = self.vendor_entry.get().strip()
        if raw.lower() == "all" or raw == "":
            return ["all"]
        return [v.strip() for v in raw.split(",") if v.strip()]

    def get_plugin_filters(self):
        raw = self.plugin_entry.get().strip()
        if raw.lower() == "all" or raw == "":
            return ["all"]
        return [p.strip() for p in raw.split(",") if p.strip()]

    def matches_plugin_filter(self, target_class, plugin_class, search_terms, search_type):
        """
        Check if a plugin/target class matches the search criteria based on the search type.
        """
        if search_terms == ["all"]:
            return True

        for term in search_terms:
            # Check both target class and plugin class
            if (self._single_term_matches(target_class, term, search_type) or
                    self._single_term_matches(plugin_class, term, search_type)):
                return True
        return False

    def _single_term_matches(self, class_name, search_term, search_type):
        """
        Check if a single search term matches the class name based on search type.
        """
        if search_type == "exact":
            return class_name.lower() == search_term.lower()

        elif search_type == "partial":
            return search_term.lower() in class_name.lower()

        elif search_type == "starts_with":
            return class_name.lower().startswith(search_term.lower())

        elif search_type == "fuzzy":
            # Use fuzzy matching with a threshold
            similarity = SequenceMatcher(None, search_term.lower(), class_name.lower()).ratio()
            return similarity >= 0.6  # 60% similarity threshold

        elif search_type == "regex":
            try:
                pattern = re.compile(search_term, re.IGNORECASE)
                return bool(pattern.search(class_name))
            except re.error:
                # If regex is invalid, fall back to partial matching
                return search_term.lower() in class_name.lower()

        return False

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

        # Collect ALL plugins first, before filtering
        all_plugins = defaultdict(lambda: defaultdict(list))  # {type: {area: [dict]}}

        for file in self.find_di_files():
            # Determine area from path. Default to "global" if di.xml is directly under etc
            area = "global"
            m = re.search(r"/etc/([^/]+)/", file.replace("\\", "/"))
            if m:
                area = m.group(1)

            # Respect area filters only when "include all" is OFF
            if not (hasattr(self, "include_all_areas") and self.include_all_areas.get() == 1):
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

        # Store all plugins for filtering
        self.all_plugins_data = {}
        for target, area_data in all_plugins.items():
            self.all_plugins_data[target] = {}
            for area, entries in area_data.items():
                seen = set()
                deduped = []
                for entry in entries:
                    key = (entry["class"], entry["name"])
                    if key not in seen:
                        seen.add(key)
                        deduped.append(entry)
                self.all_plugins_data[target][area] = sorted(deduped, key=lambda x: x["class"])

        self.loading_label.config(text="")

        # Apply plugin filtering and display
        self.filter_plugins_live()

    def filter_plugins_live(self):
        """
        Filter the plugins based on current search criteria without re-scanning.
        """
        if not self.all_plugins_data:
            return

        plugin_filter = self.get_plugin_filters()
        search_type = self.search_type.get()

        # Filter plugins based on search criteria
        self.results = {}
        for target, area_data in self.all_plugins_data.items():
            # Check if any plugin in this target matches the filter
            target_matches = False
            filtered_areas = {}

            for area, entries in area_data.items():
                matching_entries = []
                for entry in entries:
                    if self.matches_plugin_filter(target, entry["class"], plugin_filter, search_type):
                        matching_entries.append(entry)
                        target_matches = True

                if matching_entries:
                    filtered_areas[area] = matching_entries

            if target_matches and filtered_areas:
                self.results[target] = filtered_areas

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

        total_targets = len(self.results)
        total_plugins = sum(sum(len(entries) for entries in areas.values()) for areas in self.results.values())

        # Update results counter
        self.results_label.config(text=f"Found {total_targets} target classes with {total_plugins} plugins")

        for target, areas in sorted_targets:
            count = sum(len(entries) for entries in areas.values())
            label = f"{target} ({count})"
            target_node = self.tree.insert("", "end", values=(label, "", ""))
            for area, entries in sorted(areas.items()):
                for entry in entries:
                    self.tree.insert(target_node, "end", values=(f"↳ {area}", entry["class"], entry["module"]))

    def get_plugin_suggestions(self, partial_term, max_suggestions=10):
        """
        Get plugin/target class name suggestions for autocomplete functionality.
        """
        if not self.all_plugins_data or len(partial_term) < 2:
            return []

        suggestions = set()
        partial_lower = partial_term.lower()

        for target_class in self.all_plugins_data.keys():
            if target_class.lower().startswith(partial_lower):
                suggestions.add(target_class)
            elif len(suggestions) < max_suggestions and partial_lower in target_class.lower():
                suggestions.add(target_class)

        # Also check plugin class names
        for target, area_data in self.all_plugins_data.items():
            for area, entries in area_data.items():
                for entry in entries:
                    plugin_class = entry["class"]
                    if plugin_class.lower().startswith(partial_lower):
                        suggestions.add(plugin_class)
                    elif len(suggestions) < max_suggestions and partial_lower in plugin_class.lower():
                        suggestions.add(plugin_class)

        return sorted(list(suggestions))[:max_suggestions]

    def export_json(self):
        if not self.results:
            messagebox.showwarning("No Data", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if path:
            # Include search metadata in export
            export_data = {
                "search_criteria": {
                    "plugin_filter": self.plugin_entry.get(),
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
                    [f"# Search: {self.plugin_entry.get()}, Type: {self.search_type.get()}, Vendor: {self.vendor_entry.get()}"])
                writer.writerow(["Target Class", "Area", "Plugin Class", "Plugin Name", "Module"])
                for target, areas in self.results.items():
                    for area, entries in areas.items():
                        for entry in entries:
                            writer.writerow([target, area, entry["class"], entry["name"], entry["module"]])
            messagebox.showinfo("Exported", f"Exported to {path}")


# Example of how to use the enhanced search functionality
if __name__ == "__main__":
    # This would normally be called from your main application
    root = tk.Tk()
    app = PluginMapperApp(root, "/path/to/magento/root")
    root.mainloop()