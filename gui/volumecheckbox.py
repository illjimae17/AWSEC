import tkinter as tk
from tkinter import ttk

class VolumeCheckbox(ttk.Frame):
    def __init__(self, master, volume_info, command):
        super().__init__(master)
        self.volume_info = volume_info # (instance_name, volume_id, device, size_gb_str, is_root_str)
        self.command = command
        self.var = tk.BooleanVar()
        self.checkbox = ttk.Checkbutton(
            self, 
            text=f"{volume_info[1]} ({volume_info[2]}, {volume_info[3]})", # vol_id (device, size)
            variable=self.var,
            command=self.on_check
        )
        self.checkbox.pack(anchor=tk.W)
        
    def on_check(self):
        # The command will now handle the single-selection logic
        self.command(self.volume_info[1], self.var.get())