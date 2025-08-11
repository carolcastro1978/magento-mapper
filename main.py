import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

from event_mapper import MagentoEventScannerApp
from preference_mapper import PreferenceMapperApp
from plugin_mapper import PluginMapperApp

class EntryScreenApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Magento Mapper Launcher")
        self.root.geometry("420x280")

        ttk.Label(root, text="Magento 2 Root Path:", font=("Arial", 12)).pack(pady=(20, 5))
        self.path_entry = ttk.Entry(root, width=50)
        self.path_entry.insert(0, "/Users/ccastro/Projects/Bold/magento2-projects/magento-community-booster/")
        self.path_entry.pack(pady=5)
        ttk.Button(root, text="Browse", command=self.browse_path).pack()

        ttk.Label(root, text="Select a tool:", font=("Arial", 12)).pack(pady=(20, 5))
        ttk.Button(root, text="🔍 Event Observer Mapper", width=30, command=self.launch_event_mapper).pack(pady=5)
        ttk.Button(root, text="🔧 Preference Class Mapper", width=30, command=self.launch_preference_mapper).pack(pady=5)
        ttk.Button(root, text="🧩 Plugin Mapper", width=30, command=self.launch_plugin_mapper).pack(pady=5)

    def browse_path(self):
        folder = filedialog.askdirectory()
        if folder:
            self.path_entry.delete(0, 'end')
            self.path_entry.insert(0, folder)

    def get_magento_path(self):
        path = self.path_entry.get().strip()
        if not path:
            messagebox.showerror("Error", "Please provide a Magento root path.")
            return None
        return path

    def launch_event_mapper(self):
        path = self.get_magento_path()
        if path:
            self.root.withdraw()
            new_win = tk.Toplevel(self.root)
            new_win.title("Magento 2 Event Observer Scanner")
            MagentoEventScannerApp(new_win, path)

    def launch_preference_mapper(self):
        path = self.get_magento_path()
        if path:
            self.root.withdraw()
            new_win = tk.Toplevel(self.root)
            new_win.title("Magento 2 Preference Mapper")
            PreferenceMapperApp(new_win, path)

    def launch_plugin_mapper(self):
        path = self.get_magento_path()
        if path:
            self.root.withdraw()
            new_win = tk.Toplevel(self.root)
            new_win.title("Magento 2 Plugin Mapper")
            PluginMapperApp(new_win, path)

if __name__ == "__main__":
    root = tk.Tk()
    app = EntryScreenApp(root)
    root.mainloop()