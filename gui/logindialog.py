import tkinter as tk
from tkinter import ttk, simpledialog

class LoginDialog(simpledialog.Dialog):
    def __init__(self, parent, title):
        self.result = None
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text="AWS Access Key ID:").grid(row=0, sticky=tk.W, pady=5)
        self.access_key_entry = ttk.Entry(master, width=40)
        self.access_key_entry.grid(row=0, column=1, pady=5)

        ttk.Label(master, text="AWS Secret Access Key:").grid(row=1, sticky=tk.W, pady=5)
        self.secret_key_entry = ttk.Entry(master, width=40, show="*")
        self.secret_key_entry.grid(row=1, column=1, pady=5)

        ttk.Label(master, text="AWS Region:").grid(row=2, sticky=tk.W, pady=5)
        self.region_entry = ttk.Entry(master, width=40)
        self.region_entry.grid(row=2, column=1, pady=5)
        self.region_entry.insert(0, "us-east-1") # Default region

        ttk.Label(master, text="Investigator Name/Email:").grid(row=3, sticky=tk.W, pady=5)
        self.investigator_entry = ttk.Entry(master, width=40)
        self.investigator_entry.grid(row=3, column=1, pady=5)

        return self.access_key_entry # initial focus

    def apply(self):
        self.result = (
            self.access_key_entry.get(),
            self.secret_key_entry.get(),
            self.region_entry.get(),
            self.investigator_entry.get()
        )