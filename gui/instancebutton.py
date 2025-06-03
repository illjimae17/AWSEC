import tkinter as tk
from tkinter import ttk

class InstanceButton(ttk.Frame):
    def __init__(self, master, instance, command):
        super().__init__(master, style='Instance.TFrame')
        self.instance = instance
        self.command = command
        
        self.style = ttk.Style()
        self.style.configure('Instance.TFrame', background='#f0f0f0', borderwidth=2, relief='groove')
        self.style.configure('Instance.TLabel', background='#f0f0f0')
        self.style.configure('InstanceSelected.TFrame', background='#e0e0ff', borderwidth=2, relief='sunken')
        
        self.id_label = ttk.Label(self, text=f"ID: {instance['InstanceId']}", style='Instance.TLabel')
        self.id_label.grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        
        self.name_label = ttk.Label(self, text=f"Name: {instance['Name']}", style='Instance.TLabel')
        self.name_label.grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        
        self.type_label = ttk.Label(self, text=f"Type: {instance['InstanceType']}", style='Instance.TLabel')
        self.type_label.grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        
        state_color = '#4CAF50' if instance['State'] == 'running' else '#FF9800' if instance['State'] == 'stopped' else '#F44336'
        self.state_label = ttk.Label(self, text=f"State: {instance['State']}", style='Instance.TLabel', foreground=state_color)
        self.state_label.grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        
        self.bind("<Button-1>", self.on_click)
        for child in self.winfo_children():
            child.bind("<Button-1>", self.on_click)
        
        self.selected = False
        
    def on_click(self, event):
        # This method now just toggles visual state. Actual selection logic is in ForensicGUI.on_instance_select
        self.command(self.instance, not self.selected) # Pass the new potential state