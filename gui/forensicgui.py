import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
import boto3
import paramiko
import os
import time
import sys
from datetime import datetime
import threading
import json
import hashlib
import queue
# from PIL import Image, ImageTk # PIL/Pillow is not used in the current version
import subprocess
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from .logindialog import LoginDialog
from .instancebutton import InstanceButton
from .volumecheckbox import VolumeCheckbox
import multiprocessing

# ===================== GUI CLASSES =====================
class ForensicGUI:
    def __init__(self, root):
        self.cancellation_requested = False
        self.root = root
        # Set window icon
        try:
            # Set icon for main window
            self.root.iconbitmap("LOGO.ico")
        except Exception:
            pass  # Ignore if icon file is missing or on non-Windows platforms
        self.root.title("AWS EC2 Evidence Gathering Tool")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        self.style.configure('Status.TLabel', font=('Arial', 10, 'bold'))
        self.style.configure('Success.TLabel', foreground='green')
        self.style.configure('Error.TLabel', foreground='red')
        self.style.configure('Warning.TLabel', foreground='orange')
        
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.setup_instance_selection_tab()
        self.setup_forensic_tab()
        self.setup_logs_tab()
        
        self.session = None
        self.investigator = ""
        self.instances = []
        self.selected_instances = [] # Should only contain one instance at a time
        self.volumes = {} # All volumes for the selected instance: {vol_id: data}
        self.selected_volumes = {} # Should only contain one volume: {vol_id: data}
        self.forensic_instance = None # Details of the created forensic EC2 instance
        self.ssh_client = None
        self.log_queue = queue.Queue()
        self.stop_loading_flag = False # For simple loading animations, not used for main process
        self.output_dir = None
        self.coc_data = []
        self.integrity_data = []
        self.report_data = []
        self.current_volume_original_state = None # Stores info for restoration on cancellation

        self.loading_screen = ttk.Frame(self.main_frame) # General loading screen
        self.loading_label = ttk.Label(self.loading_screen, text="", style='Header.TLabel')
        self.loading_label.pack(expand=True)
        
        self.monitor_log_queue()
        self.disable_tabs([0, 1, 2]) # Disable all initially

        # Handle window close button
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.show_login()

    def on_closing(self):
        """Handles the event of closing the window."""
        # Check if forensic process is running (start_btn is disabled, cancel_btn is enabled)
        if self.start_btn['state'] == tk.DISABLED and self.cancel_btn['state'] == tk.NORMAL:
            messagebox.showwarning("Process Running",
                                   "A forensic process is currently running. "
                                   "Please use the 'Cancel' button to stop the process before closing the application.")
            return  # Prevent closing
        self.root.destroy()

    def show_loading_screen(self, message):
        """Show loading screen with message"""
        self.loading_label.config(text=message)
        self.loading_screen.pack(fill=tk.BOTH, expand=True)
        self.loading_screen.lift() # Ensure it's on top
        self.main_frame.update()
        
    def hide_loading_screen(self):
        """Hide loading screen"""
        self.loading_screen.pack_forget()
        
    def show_login(self):
        """Show login dialog"""
        self.root.lift()
        # self.root.attributes('-topmost', True)
        self.root.after(500, lambda: self.root.attributes('-topmost', False))
        login = LoginDialog(self.root, "AWS Login")
        if login.result:
            access_key, secret_key, region, investigator_name = login.result
            self.investigator = investigator_name # Store investigator name
            self.validate_credentials(access_key, secret_key, region, investigator_name)
        else: # Login cancelled
            self.root.destroy() # Close app if login is cancelled

    def setup_instance_selection_tab(self):
        """Setup the instance selection tab"""
        self.instance_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.instance_tab, text="Instance Selection")
        
        # Header
        header_frame = ttk.Frame(self.instance_tab)
        header_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(header_frame, text="EC2 Instance Selection (Select One)", style='Header.TLabel').pack(side=tk.LEFT, padx=10)
        
        self.refresh_btn = ttk.Button(header_frame, text="Refresh Instances", command=self.refresh_instances)
        self.refresh_btn.pack(side=tk.RIGHT, padx=5)
        
        # Instance selection frame
        self.instance_container = ttk.Frame(self.instance_tab)
        self.instance_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.canvas = tk.Canvas(self.instance_container, bg='#f0f0f0', highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.instance_container, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas) # This frame will hold InstanceButton widgets
        
        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Volume selection frame
        self.volume_frame = ttk.LabelFrame(self.instance_tab, text="Select Volume for Forensic Imaging (Select One)")
        self.volume_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.vol_canvas = tk.Canvas(self.volume_frame, bg='#f0f0f0', highlightthickness=0)
        self.vol_scrollbar = ttk.Scrollbar(self.volume_frame, orient="vertical", command=self.vol_canvas.yview)
        self.vol_scrollable_frame = ttk.Frame(self.vol_canvas)

        self.vol_scrollable_frame.bind(
            "<Configure>",
            lambda e: self.vol_canvas.configure(scrollregion=self.vol_canvas.bbox("all"))
        )

        self.vol_canvas.create_window((0, 0), window=self.vol_scrollable_frame, anchor="nw")

        self.vol_canvas.configure(yscrollcommand=self.vol_scrollbar.set)

        # Make the canvas expand and fill available space
        self.vol_canvas.pack(side="left", fill="both", expand=True)
        self.vol_scrollbar.pack(side="right", fill="y")

        # Make the volume_frame propagate resizing to its children
        self.volume_frame.pack_propagate(False)
        self.volume_frame.rowconfigure(0, weight=1)
        self.volume_frame.columnconfigure(0, weight=1)
        self.vol_canvas.bind("<Configure>", lambda e: self.vol_canvas.itemconfig(1, width=e.width))
        # Continue button
        # Use a dedicated frame and pack with side/bottom anchor to keep button visible on resize
        btn_frame = ttk.Frame(self.instance_tab)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=10)
        self.continue_btn = ttk.Button(btn_frame, text="Continue to Gathering Process", command=self.prepare_forensic_tab)
        self.continue_btn.pack(pady=0)
        self.continue_btn.config(state=tk.DISABLED)
        
        self.instance_status_label = ttk.Label(self.instance_tab, text="", style='Status.TLabel')
        self.instance_status_label.pack(pady=5)

    def prepare_forensic_tab(self):
        """Prepare the forensic tab with selected volume"""
        if not self.selected_volumes or len(self.selected_volumes) != 1:
            messagebox.showwarning("No Volume Selected", "Please select exactly one volume to continue.")
            return
        
        self.enable_tabs([1,2]) # Enable Forensic and Logs tabs
        self.notebook.select(1) # Switch to Forensic Process tab
        
        vol_id = list(self.selected_volumes.keys())[0]
        vol_data = self.selected_volumes[vol_id]
        selected_text = f"{vol_id} (Device: {vol_data['device']}, Instance: {vol_data['instance']['InstanceId']})"
        
        self.status_text.config(state=tk.NORMAL)
        self.status_text.delete("1.0", tk.END)
        self.status_text.insert(tk.END, f"Selected volume for forensic imaging:\n{selected_text}")
        self.status_text.config(state=tk.DISABLED)

    def setup_forensic_tab(self):
        """Setup the forensic process tab"""
        self.forensic_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.forensic_tab, text="Gathering Process")
        
        header = ttk.Label(self.forensic_tab, text="Evidence Gathering Process", style='Header.TLabel')
        header.pack(pady=10)
        
        config_frame = ttk.Frame(self.forensic_tab)
        config_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(config_frame, text="SSH Key File (.pem):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.key_path_entry = ttk.Entry(config_frame, width=50)
        self.key_path_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        browse_btn = ttk.Button(config_frame, text="Browse", command=self.browse_key_file)
        browse_btn.grid(row=0, column=2, padx=5)
        
        ttk.Label(config_frame, text="Encryption Passphrase:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.passphrase_entry = ttk.Entry(config_frame, width=50, show="*")
        self.passphrase_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(config_frame, text="Output Directory:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.output_dir_entry = ttk.Entry(config_frame, width=50)
        self.output_dir_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        browse_output_btn = ttk.Button(config_frame, text="Browse", command=self.browse_output_dir)
        browse_output_btn.grid(row=2, column=2, padx=5)
        
        progress_frame = ttk.Frame(self.forensic_tab)
        progress_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        ttk.Label(progress_frame, text="Overall Progress:").pack(anchor=tk.W)
        self.overall_progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.overall_progress.pack(fill=tk.X, pady=5)
        
        ttk.Label(progress_frame, text="Current Step Progress:").pack(anchor=tk.W)
        self.step_progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.step_progress.pack(fill=tk.X, pady=5)
        
        self.status_text = scrolledtext.ScrolledText(progress_frame, height=10, wrap=tk.WORD, font=('Consolas', 9))
        self.status_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.status_text.config(state=tk.DISABLED)
        
        btn_frame = ttk.Frame(self.forensic_tab)
        btn_frame.pack(pady=10)
        
        self.start_btn = ttk.Button(
            btn_frame, 
            text="Start Evidence Gathering Process", 
            command=self.start_forensic_process
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.cancel_process, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)
        
        self.forensic_status_label = ttk.Label(self.forensic_tab, text="", style='Status.TLabel')
        self.forensic_status_label.pack(pady=5)

    def export_all_logs(self):
        """Export only the GUI log to a .log file (no zip, no output_dir files)"""
        try:
            log_path = filedialog.asksaveasfilename(
                defaultextension=".log",
                filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")],
                title="Save GUI Log As"
            )
            if not log_path:
                return

            gui_log_content = self.log_text.get("1.0", tk.END)
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(gui_log_content)

            self.log_message(f"GUI log exported to {log_path}", 'success')
        except Exception as e:
            self.log_message(f"Export failed: {str(e)}", 'error')
            messagebox.showerror("Export Error", f"Failed to export log: {str(e)}")

    def generate_report(self):
        try:
            if not self.output_dir:
                messagebox.showerror("Error", "No output directory specified for the report.")
                return
            if not self.report_data:
                messagebox.showinfo("No Data", "No forensic data available to generate a report.")
                return

            report_path = os.path.join(self.output_dir, f"forensic_summary_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            c = canvas.Canvas(report_path, pagesize=letter)
            width, height = letter
            
            c.setFont("Helvetica-Bold", 16)
            c.drawString(72, height - 72, "Evidence Gathering Summary Report")
            
            y_position = height - 100
            c.setFont("Helvetica", 12)
            c.drawString(72, y_position, f"Investigator: {self.investigator}")
            y_position -= 20
            c.drawString(72, y_position, f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            y_position -= 20
            c.drawString(72, y_position, f"Total Cases Processed: {len(self.report_data)}")
            
            y_position -= 40
            c.setFont("Helvetica-Bold", 14)
            c.drawString(72, y_position, "Chain of Custody Details:")
            y_position -= 20
            
            c.setFont("Helvetica", 10)
            for case_data in self.report_data: # case_id, volume_id, collection_time
                case_id, volume_id, date_str = case_data
                
                if y_position < 100: # New page if not enough space
                    c.showPage()
                    y_position = height - 72
                    c.setFont("Helvetica-Bold", 14)
                    c.drawString(72, y_position, "Chain of Custody Details (Continued):")
                    y_position -= 20
                    c.setFont("Helvetica", 10)

                c.drawString(80, y_position, f"Case ID: {case_id}")
                y_position -= 15
                c.drawString(80, y_position, f"Volume ID: {volume_id}")
                y_position -= 15
                c.drawString(80, y_position, f"Collection Date: {date_str}")
                y_position -= 25 # Extra space between entries
            
            if y_position < 200 and self.integrity_data : # Check for space before starting next section
                 c.showPage()
                 y_position = height - 72

            if self.integrity_data:
                c.setFont("Helvetica-Bold", 14)
                c.drawString(72, y_position, "Evidence Integrity Summary:")
                y_position -= 20
                
                c.setFont("Helvetica", 10)
                for entry in self.integrity_data:
                    if y_position < 150: # New page
                        c.showPage()
                        y_position = height - 72
                        c.setFont("Helvetica-Bold", 14)
                        c.drawString(72, y_position, "Evidence Integrity Summary (Continued):")
                        y_position -= 20
                        c.setFont("Helvetica", 10)

                    c.drawString(80, y_position, f"Volume ID: {entry['volume_id']}")
                    y_position -= 15
                    c.drawString(80, y_position, f"Hash Match (Downloaded vs Encrypted on Forensic): {entry['hash_match']}")
                    y_position -= 15
                    c.drawString(80, y_position, f"Encrypted: {entry['encrypted']}")
                    y_position -= 15
                    c.drawString(80, y_position, f"SHA256 (Raw Image on Forensic): {entry['raw_hash']}")
                    y_position -= 15
                    c.drawString(80, y_position, f"SHA256 (Encrypted Image on Forensic): {entry['encrypted_hash']}")
                    y_position -= 15
                    c.drawString(80, y_position, f"SHA256 (Encrypted Image on Local): {entry.get('encrypted_local_hash', 'N/A')}")
                    y_position -= 15
            
            c.save()
            self.log_message(f"Report generated at {report_path}", 'success')
            messagebox.showinfo("Report Generated", f"Evidence Gathering report saved to:\n{report_path}")
        except Exception as e:
            self.log_message(f"Report generation failed: {str(e)}", 'error')
            messagebox.showerror("Report Error", f"Failed to generate report: {str(e)}")

    def open_case_folder(self):
        """Open the output directory in file explorer"""
        try:
            if not self.output_dir or not os.path.exists(self.output_dir):
                messagebox.showerror("Error", "Case folder not found or not specified.")
                return

            if sys.platform == "win32":
                os.startfile(os.path.normpath(self.output_dir))
            elif sys.platform == "darwin": # macOS
                subprocess.run(["open", self.output_dir])
            else: # Linux and other Unix-like
                subprocess.run(["xdg-open", self.output_dir])
        except Exception as e:
            self.log_message(f"Couldn't open folder: {str(e)}", 'error')
            messagebox.showerror("Error", f"Could not open case folder: {str(e)}")
        
    def setup_logs_tab(self):
        self.logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_tab, text="Logs & Results") # Initially enabled but content updates later
        
        paned = ttk.PanedWindow(self.logs_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        log_frame = ttk.Frame(paned, width=600) # Give initial width hint
        log_frame.pack_propagate(False) # Prevent frame from shrinking
        ttk.Label(log_frame, text="Process Logs (GUI Messages)", style='Header.TLabel').pack(pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED) # Start disabled
        
        result_frame = ttk.Frame(paned, width=400) # Give initial width hint
        result_frame.pack_propagate(False)
        ttk.Label(result_frame, text="Evidence Gathering Summary", style='Header.TLabel').pack(pady=5)
        
        result_notebook = ttk.Notebook(result_frame)
        
        coc_frame = ttk.Frame(result_notebook)
        self.coc_tree = ttk.Treeview(coc_frame, columns=('CaseID', 'VolumeID', 'Status', 'Timestamp'), show='headings')
        self.coc_tree.heading('CaseID', text='Case ID', anchor=tk.W)
        self.coc_tree.heading('VolumeID', text='Volume ID', anchor=tk.W)
        self.coc_tree.heading('Status', text='Status', anchor=tk.W)
        self.coc_tree.heading('Timestamp', text='Timestamp', anchor=tk.W)
        self.coc_tree.column('CaseID', width=200, anchor=tk.W)
        self.coc_tree.column('VolumeID', width=150, anchor=tk.W)
        self.coc_tree.column('Status', width=100, anchor=tk.W)
        self.coc_tree.column('Timestamp', width=150, anchor=tk.W)
        self.coc_tree.pack(fill=tk.BOTH, expand=True)
        result_notebook.add(coc_frame, text="Chain of Custody")
        
        integrity_frame = ttk.Frame(result_notebook)
        self.integrity_tree = ttk.Treeview(integrity_frame, 
                                           columns=('VolumeID', 'HashMatch', 'Encrypted'), 
                                           show='headings')
        self.integrity_tree.heading('VolumeID', text='Volume ID', anchor=tk.W)
        self.integrity_tree.heading('HashMatch', text='Hash Match', anchor=tk.W)
        self.integrity_tree.heading('Encrypted', text='Encrypted', anchor=tk.W)
        self.integrity_tree.column('VolumeID', width=150, anchor=tk.W)
        self.integrity_tree.column('HashMatch', width=100, anchor=tk.W)
        self.integrity_tree.column('Encrypted', width=80, anchor=tk.W)
        self.integrity_tree.pack(fill=tk.BOTH, expand=True)
        result_notebook.add(integrity_frame, text="Evidence Integrity")
        
        result_notebook.pack(fill=tk.BOTH, expand=True)
        paned.add(log_frame, weight=2) # Give more weight to logs
        paned.add(result_frame, weight=1)
        
        btn_frame_logs_tab = ttk.Frame(self.logs_tab) # Use a different name
        btn_frame_logs_tab.pack(pady=10)
        
        ttk.Button(btn_frame_logs_tab, text="Export All Collected logs", command=self.export_all_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame_logs_tab, text="Generate Summary Report", command=self.generate_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame_logs_tab, text="Open Case Folder", command=self.open_case_folder).pack(side=tk.LEFT, padx=5)
        
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

    # ===================== GUI HELPER METHODS =====================

    def on_tab_change(self, event):
        try:
            current_tab_index = self.notebook.index("current")
            if current_tab_index == 2: # Logs & Results tab
                self.update_results_tables()
        except tk.TclError:
            # This can happen if the notebook is empty or tab is not valid
            pass

    def update_results_tables(self):
        # Clear existing items
        for item in self.coc_tree.get_children():
            self.coc_tree.delete(item)
        for item in self.integrity_tree.get_children():
            self.integrity_tree.delete(item)
        
        # Populate CoC table
        for entry in self.coc_data:
            self.coc_tree.insert('', 'end', values=(
                entry.get('case_id', 'N/A'),
                entry.get('volume_id', 'N/A'),
                entry.get('status', 'N/A'),
                entry.get('timestamp', 'N/A')
            ))
        
        # Populate Integrity table
        for entry in self.integrity_data:
            self.integrity_tree.insert('', 'end', values=(
                entry.get('volume_id', 'N/A'),
                entry.get('hash_match', 'N/A'),
                entry.get('encrypted', 'N/A')
            ))

    def disable_tabs(self, tab_indices):
        """Disable specific tabs by index"""
        for idx in tab_indices:
            try:
                self.notebook.tab(idx, state=tk.DISABLED)
            except tk.TclError:
                self.log_message(f"Warning: Could not disable tab index {idx}.", "warning")
            
    def enable_tabs(self, tab_indices):
        """Enable specific tabs by index"""
        for idx in tab_indices:
            try:
                self.notebook.tab(idx, state=tk.NORMAL)
            except tk.TclError:
                 self.log_message(f"Warning: Could not enable tab index {idx}.", "warning")
            
    def update_status(self, widget, message, status_type='info'):
        """Update status labels with colored text"""
        if not widget: return
        widget.config(text=message)
        if status_type == 'success':
            widget.config(style='Success.TLabel')
        elif status_type == 'error':
            widget.config(style='Error.TLabel')
        elif status_type == 'warning':
            widget.config(style='Warning.TLabel')
        else: # info
            widget.config(style='Status.TLabel') # Use Status.TLabel for default info
            
    def log_message(self, message, status='info', timestamp=True, newline=True):
        # Removed the time-based throttling from here to ensure all messages are queued.
        # The monitor_log_queue handles batching for GUI updates.
        
        if timestamp:
            timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] # Milliseconds
            color_map = {'error': "red", 'warning': "orange", 'success': "green", 'info': "black", 'critical_warning': 'purple'}
            prefix_map = {'error': "ERROR", 'warning': "WARN", 'success': "SUCCESS", 'info': "INFO", 'critical_warning': 'CRITICAL WARN'}
            
            color = color_map.get(status, "black")
            prefix = prefix_map.get(status, "INFO")
            log_entry = f"[{prefix} {timestamp_str}] {message}"
        else:
            log_entry = message
            color = "grey" # For non-timestamped, often direct command output

        if newline:
            log_entry += "\n"
            
        self.log_queue.put((log_entry, color))
        
    def monitor_log_queue(self):
        """Monitor the log queue and update the GUI log text areas"""
        try:
            # Process up to a small batch of messages to prevent UI freeze
            for _ in range(20): # Process more messages if available
                if self.log_queue.empty():
                    break
                message, color = self.log_queue.get_nowait()
                
                # Append to forensic process status_text (ScrolledText in Forensic Tab)
                if hasattr(self, 'status_text') and self.status_text.winfo_exists():
                    self.status_text.config(state=tk.NORMAL)
                    self.status_text.insert(tk.END, message, color) # Use tuple for tag
                    self.status_text.tag_configure(color, foreground=color) # Ensure tag is configured
                    self.status_text.see(tk.END)
                    self.status_text.config(state=tk.DISABLED)

                # Append to general log_text (ScrolledText in Logs Tab)
                if hasattr(self, 'log_text') and self.log_text.winfo_exists():
                    self.log_text.config(state=tk.NORMAL)
                    self.log_text.insert(tk.END, message, color) # Use tuple for tag
                    self.log_text.tag_configure(color, foreground=color) # Ensure tag is configured
                    self.log_text.see(tk.END)
                    self.log_text.config(state=tk.DISABLED)

        except queue.Empty:
            pass
        except Exception as e:
            # Fallback logging if GUI elements are problematic
            print(f"Error in monitor_log_queue: {e}")
        finally:
            if hasattr(self, 'root') and self.root.winfo_exists():
                self.root.after(100, self.monitor_log_queue) # Check queue every 100ms

    def browse_key_file(self):
        """Browse for SSH key file"""
        file_path = filedialog.askopenfilename(title="Select SSH Key File", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if file_path:
            self.key_path_entry.delete(0, tk.END)
            self.key_path_entry.insert(0, file_path)
            
    def browse_output_dir(self):
        """Browse for output directory"""
        dir_path = filedialog.askdirectory(title="Select Output Directory")
        if dir_path:
            self.output_dir_entry.delete(0, tk.END)
            self.output_dir_entry.insert(0, dir_path)
            self.output_dir = dir_path # Store it directly
            
    def check_continue_button(self):
        """Enable/disable continue button based on selections"""
        # Requires one instance and one volume selected
        if len(self.selected_instances) == 1 and len(self.selected_volumes) == 1:
            self.continue_btn.config(state=tk.NORMAL)
        else:
            self.continue_btn.config(state=tk.DISABLED)
            
    def on_instance_select(self, instance_data, is_now_selected_visual):
        """Handle instance selection to allow only one instance."""
        clicked_instance_id = instance_data['InstanceId']

        # Update visual state of all InstanceButton widgets
        newly_selected_instance_obj = None
        for widget in self.scrollable_frame.winfo_children():
            if isinstance(widget, InstanceButton):
                if widget.instance['InstanceId'] == clicked_instance_id:
                    if is_now_selected_visual: # If the click intended to select this
                        widget.selected = True
                        widget.configure(style='InstanceSelected.TFrame')
                        newly_selected_instance_obj = widget.instance
                    else: # If the click intended to deselect this
                        widget.selected = False
                        widget.configure(style='Instance.TFrame')
                else: # For all other instances, ensure they are visually deselected
                    widget.selected = False
                    widget.configure(style='Instance.TFrame')
        
        # Update internal state (self.selected_instances)
        if newly_selected_instance_obj:
            if not self.selected_instances or self.selected_instances[0]['InstanceId'] != clicked_instance_id:
                self.selected_instances = [newly_selected_instance_obj]
                self.load_volumes_for_instance(newly_selected_instance_obj) # Load volumes for the new selection
            # If it's the same instance, selected_instances is already correct, volumes loaded.
        else: # No instance is selected (or the clicked one was deselected)
            self.selected_instances = []
            self.clear_volume_checkboxes() # Clear volumes as no instance is selected
            self.selected_volumes.clear()


        self.check_continue_button()

    def on_volume_select(self, toggled_volume_id, is_now_selected_visual):
        """Handle volume selection to allow only one volume."""
        # First, update the visual state of all VolumeCheckbox widgets
        newly_selected_volume_data = None

        for child_widget in self.vol_scrollable_frame.winfo_children():
            if isinstance(child_widget, VolumeCheckbox):
                current_widget_vol_id = child_widget.volume_info[1]
                if current_widget_vol_id == toggled_volume_id:
                    if is_now_selected_visual: # If this was the one clicked to be selected
                        child_widget.var.set(True) # Ensure it's visually checked
                        if toggled_volume_id in self.volumes:
                             newly_selected_volume_data = self.volumes[toggled_volume_id]
                        else: # Data missing, shouldn't happen if loaded correctly
                            child_widget.var.set(False) 
                            self.log_message(f"Volume data error for {toggled_volume_id}", "error")
                    else: # If this was the one clicked to be deselected
                        child_widget.var.set(False) # Ensure it's visually unchecked
                else: # For all other volumes, ensure they are visually unchecked
                    child_widget.var.set(False)
        
        # Update internal state (self.selected_volumes)
        if newly_selected_volume_data:
            self.selected_volumes = {toggled_volume_id: newly_selected_volume_data}
        else: # No volume is selected (or the clicked one was deselected / invalid)
            self.selected_volumes.clear()
            
        self.check_continue_button()

    def clear_volume_checkboxes(self):
        for child in self.vol_scrollable_frame.winfo_children():
            child.destroy()
        self.volumes.clear() # Clear the cache of all volumes for the (now deselected) instance
        # self.selected_volumes is cleared by the caller (on_instance_select or on_volume_select)

    def load_volumes_for_instance(self, instance):
        """Load volumes for a selected instance into checkboxes."""
        self.clear_volume_checkboxes() # Clear previous volumes first
        self.selected_volumes.clear() # Also clear any single selected volume

        self.show_loading_screen(f"Loading volumes for {instance.get('Name', instance['InstanceId'])}...")

        def load_thread():
            try:
                ec2 = self.session.client('ec2')
                # Filter for volumes attached to the specific instance
                response = ec2.describe_volumes(
                    Filters=[{'Name': 'attachment.instance-id', 'Values': [instance['InstanceId']]}]
                )
                
                loaded_vols_data = {}
                vol_checkbox_infos = []

                for volume in response.get('Volumes', []):
                    for attachment in volume.get('Attachments', []):
                        if attachment.get('InstanceId') == instance['InstanceId']:
                            is_root = self.is_root_volume(volume['VolumeId'], instance['InstanceId'])
                            vol_info_tuple = ( # For VolumeCheckbox display
                                instance.get('Name', instance['InstanceId']),
                                volume['VolumeId'],
                                attachment['Device'],
                                f"{volume.get('Size', 'N/A')} GB",
                                "Root" if is_root else "Data"
                            )
                            vol_checkbox_infos.append(vol_info_tuple)
                            
                            # Store full data for self.volumes
                            loaded_vols_data[volume['VolumeId']] = {
                                'info_tuple': vol_info_tuple, # The tuple used for display
                                'instance': instance, # Reference to parent instance
                                'device': attachment['Device'],
                                'is_root': is_root,
                                'volume_id': volume['VolumeId'],
                                'size_gb': volume.get('Size', 0)
                                # Add any other relevant volume details here
                            }
                            break # Found attachment for this instance, move to next volume
                self.clear_volume_checkboxes() # Clear any existing checkboxes before adding new ones
                
                self.volumes = loaded_vols_data # Update the main cache

                # Schedule GUI updates on the main thread
                if vol_checkbox_infos:
                    for vol_info_t in vol_checkbox_infos:
                        self.root.after(0, lambda v_info=vol_info_t: VolumeCheckbox(
                            self.vol_scrollable_frame,
                            v_info,
                            self.on_volume_select 
                        ).pack(anchor=tk.W, padx=5, pady=2))
                    self.root.after(0, lambda: self.update_status(self.instance_status_label,
                        f"Loaded {len(vol_checkbox_infos)} volumes for {instance.get('Name', instance['InstanceId'])}", 'success'))
                else:
                    self.root.after(0, lambda: self.update_status(self.instance_status_label,
                        f"No volumes found attached to {instance.get('Name', instance['InstanceId'])}", 'warning'))

            except Exception as e:
                self.log_message(f"Error loading volumes: {str(e)}", 'error')
                self.root.after(0, lambda: self.update_status(self.instance_status_label,
                    f"Error loading volumes: {e}", 'error'))
            finally:
                self.root.after(0, self.hide_loading_screen)
                self.root.after(0, self.check_continue_button) # Update button state after loading

        threading.Thread(target=load_thread, daemon=True).start()
        
    # ===================== AWS OPERATIONS =====================
    def validate_credentials(self, access_key, secret_key, region, investigator_name):
        """Validate AWS credentials"""
        if not all([access_key, secret_key, region, investigator_name]):
            messagebox.showerror("Input Error", "All login fields are required.")
            self.show_login() # Re-show login
            return

        self.show_loading_screen("Validating AWS credentials...")
        
        def validate_thread():
            session= None
            try:
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region
                )
                ec2_client = session.client('ec2')
                ec2_client.describe_regions() # A simple call to check credentials and region
                
                self.session = session
                self.investigator = investigator_name
                self.log_message("AWS credentials validated successfully.", 'success')
                self.root.after(0, lambda: self.update_status(self.instance_status_label, "Credentials OK. Fetching instances...", 'success'))
                self.root.after(0, lambda: self.enable_tabs([0,2])) # Enable Instance Selection and Logs
                self.root.after(0, lambda: self.notebook.select(0)) 
                self.root.after(0, self.refresh_instances)
            except Exception as e:
                # messagebox.showwarning("Error, invalid credentials", f"Invalid AWS credentials or region: {str(e)}")
                self.log_message(f"Error validating credentials: {str(e)}", 'error')
                def show_error_then_login(error):
                    self.root.lift()
                    self.root.attributes('-topmost', True)
                    messagebox.showerror("Login Failed", f"Invalid AWS credentials or region: {str(error)}")
                    self.root.attributes('-topmost', False)
                    self.show_login()  # Show login only after error dialog is closed
                self.root.after(0, lambda: show_error_then_login(e))
                self.root.after(0, show_error_then_login)
            finally:
                self.root.after(0, self.hide_loading_screen)
                self.root.lift()
                self.root.attributes('-topmost', True)
                self.root.after(500, lambda: self.root.attributes('-topmost', False))
        threading.Thread(target=validate_thread, daemon=True).start()
        
    def refresh_instances(self):
        """Refresh the list of EC2 instances"""
        if not self.session:
            self.update_status(self.instance_status_label, "AWS session not initialized. Please login.", 'error')
            return
            
        self.show_loading_screen("Fetching EC2 instances...")
        # Clear existing instance buttons and related volume info
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.selected_instances.clear()
        self.clear_volume_checkboxes()
        self.selected_volumes.clear()
        self.check_continue_button()

        def refresh_thread():
            try:
                ec2 = self.session.client('ec2')
                response = ec2.describe_instances()
                current_instances_data = []
                for reservation in response.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        instance_name = "Unnamed"
                        if 'Tags' in instance:
                            for tag in instance['Tags']:
                                if tag['Key'] == 'Name':
                                    instance_name = tag['Value']
                                    break
                        current_instances_data.append({
                            'InstanceId': instance['InstanceId'],
                            'InstanceType': instance['InstanceType'],
                            'KeyName': instance.get('KeyName', 'N/A'),
                            'SecurityGroupIds': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                            'SubnetId': instance.get('SubnetId', 'N/A'),
                            'ImageId': instance.get('ImageId', 'N/A'),
                            "State": instance.get('State', {}).get('Name', 'unknown'),
                            'Name': instance_name,
                            # Store other details needed for forensic instance creation if this is a template
                            'VpcId': instance.get('VpcId'), 
                            'AvailabilityZone': instance.get('Placement', {}).get('AvailabilityZone')
                        })
                
                self.instances = current_instances_data # Update the main list
                self.root.after(0, self.populate_instance_buttons)
                self.log_message(f"Found {len(self.instances)} instances.", 'success')
                self.root.after(0, lambda: self.update_status(self.instance_status_label, f"{len(self.instances)} instances loaded.", 'success'))
            except Exception as e:
                self.log_message(f"Error fetching instances: {str(e)}", 'error')
                self.root.after(0, lambda: self.update_status(self.instance_status_label, f"Error fetching instances: {e}", 'error'))
            finally:
                self.root.after(0, self.hide_loading_screen)
                
        threading.Thread(target=refresh_thread, daemon=True).start()
        
    def populate_instance_buttons(self):
        """Populate the instance container with instance buttons"""
        for widget in self.scrollable_frame.winfo_children(): # Clear existing
            widget.destroy()
            
        cols = 3 # Adjust for desired layout
        for i, instance_data in enumerate(self.instances):
            row, col = divmod(i, cols)
            btn = InstanceButton(
                self.scrollable_frame, 
                instance_data, 
                self.on_instance_select # Pass the method reference
            )
            btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew") # Use ew for horizontal fill
            self.scrollable_frame.grid_columnconfigure(col, weight=1)
        
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.update_status(self.instance_status_label, f"Displaying {len(self.instances)} instances.", "info")

    def start_forensic_process(self):
        """Start the forensic imaging process for the single selected volume"""
        if not self.selected_volumes or len(self.selected_volumes) != 1:
            self.update_status(self.forensic_status_label, "Please select exactly one volume.", 'error')
            messagebox.showerror("Selection Error", "Please select exactly one volume from the Instance Selection tab.")
            return
            
        key_path = self.key_path_entry.get()
        passphrase = self.passphrase_entry.get()
        self.output_dir = self.output_dir_entry.get() # Ensure self.output_dir is updated
        
        if not all([key_path, passphrase, self.output_dir]):
            self.update_status(self.forensic_status_label, "Key file, passphrase, and output directory are required.", 'error')
            messagebox.showerror("Input Error", "SSH Key, Passphrase, and Output Directory must be specified.")
            return
            
        if not os.path.isfile(key_path):
            self.update_status(self.forensic_status_label, f"Key file not found: {key_path}", 'error')
            return
            
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
                self.log_message(f"Created output directory: {self.output_dir}", "info")
            except Exception as e:
                self.update_status(self.forensic_status_label, f"Error creating output directory: {e}", 'error')
                return
        
        self.cancellation_requested = False # Reset flag
        self.notebook.tab(0, state=tk.DISABLED) # Disable Instance Selection Tab
        self.start_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)

        # Disable input fields and browse buttons during process
        self.key_path_entry.config(state=tk.DISABLED)
        self.passphrase_entry.config(state=tk.DISABLED)
        self.output_dir_entry.config(state=tk.DISABLED)
        # Find and disable browse buttons in config_frame
        for child in self.forensic_tab.winfo_children():
            if isinstance(child, ttk.Frame):
                for widget in child.winfo_children():
                    if isinstance(widget, ttk.Button) and widget['text'] == "Browse":
                        widget.config(state=tk.DISABLED)

        self.status_text.config(state=tk.NORMAL)
        self.status_text.delete("1.0", tk.END) 
        # Re-populate with current selection, as it might have been cleared by tab switch
        vol_id = list(self.selected_volumes.keys())[0]
        vol_data = self.selected_volumes[vol_id]
        selected_text_display = f"{vol_id} (Device: {vol_data['device']}, Instance: {vol_data['instance']['InstanceId']})"
        self.status_text.insert(tk.END, f"Preparing volume imaging for:\n{selected_text_display}\n\n")
        self.status_text.config(state=tk.DISABLED)

        self.overall_progress['value'] = 0
        self.step_progress['value'] = 0
        threading.Thread(target=self.run_forensic_process, daemon=True).start()

    def run_forensic_process(self):
        """Core forensic process logic for the single selected volume."""
        try:
            # Get the single selected volume (already validated in start_forensic_process)
            vol_id_to_process = list(self.selected_volumes.keys())[0]
            vol_data = self.selected_volumes[vol_id_to_process]
            
            original_instance_data = vol_data['instance']
            is_root_volume = vol_data['is_root']
            evidence_volume_size = vol_data.get('size_gb', 8) # Default if size not found

            # Store original state for potential restoration on cancellation
            self.current_volume_original_state = {
                'volume_id': vol_id_to_process,
                'original_instance_id': original_instance_data['InstanceId'],
                'original_instance_data': original_instance_data, 
                'original_device_name': vol_data['device'], # Device name on original instance
                'is_root_volume': is_root_volume,
                'was_stopped_by_tool': False 
            }
            self.log_message(f"Starting evidence gathering for volume {vol_id_to_process} (Size: {evidence_volume_size}GB) from instance {original_instance_data['InstanceId']}.", 'info')
            self.root.after(0, lambda: self.overall_progress.config(value=5))

            # 1. Create Forensic Instance
            if self.cancellation_requested: raise InterruptedError("Process cancelled by user.")
            self.log_message("Creating forensic instance...", 'info')
            instance_name_prefix = f'Forensic-{self.investigator.split("@")[0].replace(".", "")}-'[:30] 
            forensic_instance_name = f'{instance_name_prefix}{datetime.now().strftime("%Y%m%d%H%M")}'
            
            template_az = original_instance_data.get('AvailabilityZone')
            self.forensic_instance = self.create_new_instance(
                instance_name=forensic_instance_name, 
                template_instance_data=original_instance_data,
                availability_zone=template_az,
                evidence_volume_size_gb=evidence_volume_size # Pass evidence volume size
            )
            if not self.forensic_instance:
                raise Exception("Failed to create forensic instance.")
            self.log_message(f"Forensic instance {self.forensic_instance['InstanceId']} created.", 'success')
            self.root.after(0, lambda: self.overall_progress.config(value=15))

            # 2. Handle Original Instance and Volume (Stop if root, Detach, Attach to Forensic)
            if self.cancellation_requested: raise InterruptedError("Process cancelled by user.")
            self.root.after(0, lambda: self.step_progress.config(value=0)) 
            
            if is_root_volume:
                self.log_message(f"Volume {vol_id_to_process} is a root volume. Stopping original instance {original_instance_data['InstanceId']}...", 'warning')
                if not self.stop_instance(original_instance_data['InstanceId']):
                    raise Exception(f"Failed to stop original instance {original_instance_data['InstanceId']}.")
                self.current_volume_original_state['was_stopped_by_tool'] = True
                self.log_message(f"Original instance {original_instance_data['InstanceId']} stopped.", 'success')
            self.root.after(0, lambda: self.step_progress.config(value=10)) 

            if self.cancellation_requested: raise InterruptedError("Process cancelled by user.")
            self.log_message(f"Preparing to move volume {vol_id_to_process} to forensic instance...", 'info') 
            attached_device_on_forensic_ignored = self.move_volume_to_forensic(
                vol_id_to_process, 
                original_instance_data, 
                self.forensic_instance
            )
            if not attached_device_on_forensic_ignored: 
                raise Exception(f"Failed to move volume {vol_id_to_process} to forensic instance.")
            
            self.log_message(f"Volume {vol_id_to_process} successfully attached to forensic instance. Reported device (ignored for dc3dd): {attached_device_on_forensic_ignored}.", 'success')
            self.root.after(0, lambda: self.overall_progress.config(value=30)) 
            self.root.after(0, lambda: self.step_progress.config(value=50)) 

            # 3. Connect to Forensic Instance (NOW, after volume is attached)
            if self.cancellation_requested: raise InterruptedError("Process cancelled by user.")
            self.log_message(f"Connecting to forensic instance {self.forensic_instance['PublicIpAddress']}...", 'info')
            self.ssh_client = self.connect_with_retry(
                hostname=self.forensic_instance['PublicIpAddress'],
                username='ubuntu', 
                key_filename=self.key_path_entry.get()
            )
            if not self.ssh_client:
                raise Exception("Failed to connect to forensic instance via SSH.")
            self.log_message("SSH connection to forensic instance established.", 'success')
            self.root.after(0, lambda: self.overall_progress.config(value=35)) 

            # 4. Install Tools and Create Working Directory on Forensic Instance
            if self.cancellation_requested: raise InterruptedError("Process cancelled by user.")
            self.log_message("Installing evidence gathering tools (dc3dd, gpg) on forensic instance...", 'info')
            self.install_dc3dd_and_gpg()
            self.root.after(0, lambda: self.step_progress.config(value=70)) 

            working_dir = self.create_working_directory() 
            if not working_dir: raise Exception("Failed to create working directory on forensic instance.")
            self.log_message(f"Working directory {working_dir} created on forensic instance.", "info")
            self.root.after(0, lambda: self.overall_progress.config(value=40)) 

            # 5. Create Forensic Image, Hash, and Encrypt via Pipeline
            if self.cancellation_requested: raise InterruptedError("Process cancelled by user.")
            self.log_message("Starting imaging and encryption pipeline...", 'info')
            pipeline_results = self.run_imaging_and_encryption_pipeline(
                volume_id_to_image=vol_id_to_process,
                working_dir=working_dir,
                passphrase=self.passphrase_entry.get()
            )
            if not pipeline_results:
                raise Exception("Imaging and encryption pipeline failed.")

            raw_image_hash_on_forensic = pipeline_results["raw_hash"]
            encrypted_image_path = pipeline_results["encrypted_image_path"]
            raw_hash_output_path = pipeline_results["raw_hash_output_path"]
            
            self.log_message(f"Imaging and encryption pipeline completed.", 'success')
            self.log_message(f"SHA256 (Raw Stream): {raw_image_hash_on_forensic}", 'success')
            self.root.after(0, lambda: self.overall_progress.config(value=75))

            # 6. Get Encrypted Image Hash (on forensic instance)
            if self.cancellation_requested: raise InterruptedError("Process cancelled by user.")
            self.log_message("Calculating hash of encrypted image on forensic instance...", 'info')
            encrypted_image_hash_on_forensic = self.calculate_sha256_remote(encrypted_image_path)
            if not encrypted_image_hash_on_forensic:
                 self.log_message(f"Could not calculate encrypted image hash for {encrypted_image_path}.", "warning")
                 encrypted_image_hash_on_forensic = "N/A_Calculation_Failed"
            self.log_message(f"SHA256 (Encrypted on Forensic): {encrypted_image_hash_on_forensic}", 'info')
            self.root.after(0, lambda: self.step_progress.config(value=90)) 

            # 7. Download Evidence
            if self.cancellation_requested: raise InterruptedError("Process cancelled by user.")
            self.log_message(f"Downloading evidence files for {vol_id_to_process} from forensic instance...", 'info')
            files_to_download = {
                encrypted_image_path: f"{vol_id_to_process}.img.gpg",
                raw_hash_output_path: f"{vol_id_to_process}.sha256",
            }
            downloaded_file_paths = self.download_evidences_sftp(files_to_download, vol_id_to_process)
            if not downloaded_file_paths.get(encrypted_image_path): 
                raise Exception("Failed to download critical evidence files (encrypted image).")
            self.log_message("Evidence files downloaded.", 'success')
            self.root.after(0, lambda: self.overall_progress.config(value=90))
            
            # 8. Generate Chain of Custody
            if self.cancellation_requested: raise InterruptedError("Process cancelled by user.")
            self.log_message("Generating Chain of Custody documentation...", 'info') 
            self.root.after(0, lambda: self.step_progress.config(value=0)) 

            local_encrypted_image_path = downloaded_file_paths.get(encrypted_image_path)
            
            self.log_message(f"Calculating SHA256 hash of local downloaded encrypted file: {local_encrypted_image_path}...", 'info')
            downloaded_encrypted_hash_local = self.calculate_sha256_local(
                local_encrypted_image_path, 
                self.step_progress 
            ) if local_encrypted_image_path else None
            self.log_message(f"SHA256 (Local Downloaded Encrypted): {downloaded_encrypted_hash_local or 'N/A'}", 'info')
            self.log_message(f"Start Verifying Hashes and Generating Chain of Custody... (The tool might be unresponsive), DO NOT CLOSE THE TOOL!", 'critical_warning')
            self.root.after(0, lambda: self.step_progress.config(value=100)) 

            # --- YIELD TO GUI EVENT LOOP TO PREVENT FREEZE ---
            self.root.after(0, lambda: None)
            time.sleep(0.1)
            self.root.update_idletasks()
            # -------------------------------------------------

            passphrase_commitment = hashlib.sha256(self.passphrase_entry.get().encode()).hexdigest()
            
            coc_details = self.export_coc_logs(
                investigator=self.investigator,
                source_instance_data=original_instance_data,
                forensic_instance_data=self.forensic_instance,
                volume_id=vol_id_to_process,
                key_path_name=os.path.basename(self.key_path_entry.get()),
                passphrase_commitment=passphrase_commitment,
                hashes={ 
                    "raw_on_forensic": raw_image_hash_on_forensic, 
                    "encrypted_on_forensic": encrypted_image_hash_on_forensic,
                    "downloaded_encrypted_local": downloaded_encrypted_hash_local
                },
                downloaded_files_map=downloaded_file_paths,
            )
            if not coc_details:
                raise Exception("Failed to generate Chain of Custody documentation.")
            self.log_message(f"Chain of Custody generated for Case ID: {coc_details['case_id']}", 'success')
            self.root.after(0, lambda: self.overall_progress.config(value=95))
            self.root.after(0, lambda: self.step_progress.config(value=100)) 
            self.log_message("\rVolume imaging process completed successfully for the volume!", 'success')
            self.log_message("WARNING: Use the inputted passphrase to decrypt the .gpg image file.", 'critical_warning')

        except InterruptedError: 
            self.log_message("\nGathering process explicitly cancelled by user.", 'warning')
        except Exception as e:
            if not self.cancellation_requested: 
                self.log_message(f"\nGathering process failed: {str(e)}", 'error')
                import traceback
                self.log_message(traceback.format_exc(), 'error') 
        finally:
            self.root.after(0, self.cleanup_forensic_process)

            
    def cleanup_forensic_process(self):
        """Cleanup after forensic process, including resource restoration on success or cancellation."""
        self.log_message("Initiating cleanup and resource restoration...", 'info')
        
        if self.current_volume_original_state:
            state = self.current_volume_original_state
            vol_id_to_restore = state['volume_id']
            original_inst_data = state['original_instance_data']
            original_dev_name = state['original_device_name']
            was_stopped_by_tool = state['was_stopped_by_tool']
            
            self.log_message(f"Restoring volume {vol_id_to_restore} to instance {original_inst_data['InstanceId']}...", 'info')

            if self.reattach_volume_to_original(vol_id_to_restore, original_inst_data, self.forensic_instance, original_dev_name):
                self.log_message(f"Volume {vol_id_to_restore} successfully restored to original instance {original_inst_data['InstanceId']} as {original_dev_name}.", 'success')
                if was_stopped_by_tool:
                    self.log_message(f"Original instance {original_inst_data['InstanceId']} was stopped by the tool. Attempting restart...", 'info')
                    if self.start_instance(original_inst_data['InstanceId']):
                        self.log_message(f"Original instance {original_inst_data['InstanceId']} restarted.", 'success')
                    else:
                        self.log_message(f"Failed to restart original instance {original_inst_data['InstanceId']}. Manual check may be needed.", 'error')
            else:
                self.log_message(f"Failed to restore volume {vol_id_to_restore} to original instance. Manual intervention required.", 'error')
        else:
            self.log_message("No specific volume state to restore (process might have failed early or was not a volume operation).", "warning")

        if self.ssh_client:
            try:
                self.log_message("Closing SSH connection to forensic instance...", 'info')
                self.ssh_client.close()
            except Exception as e_ssh:
                self.log_message(f"Error closing SSH connection: {e_ssh}", 'warning')
            finally:
                self.ssh_client = None
        
        if self.forensic_instance and self.forensic_instance.get('InstanceId'):
            self.log_message(f"Terminating forensic instance {self.forensic_instance['InstanceId']}...", 'warning')
            if self.terminate_instance(self.forensic_instance['InstanceId']):
                self.log_message(f"Forensic instance {self.forensic_instance['InstanceId']} terminated.", 'success')
            else:
                self.log_message(f"Failed to terminate forensic instance {self.forensic_instance['InstanceId']}. Please check AWS console.", 'error')
        
        self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.cancel_btn.config(state=tk.DISABLED))
        self.root.after(0, lambda: self.notebook.tab(0, state=tk.NORMAL))
        self.root.after(0, lambda: self.overall_progress.config(value=0))
        self.root.after(0, lambda: self.step_progress.config(value=0))
        # Re-enable input fields and browse buttons after process
        self.root.after(0, lambda: self.key_path_entry.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.passphrase_entry.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.output_dir_entry.config(state=tk.NORMAL))
        def enable_browse_buttons():
            for child in self.forensic_tab.winfo_children():
                if isinstance(child, ttk.Frame):
                    for widget in child.winfo_children():
                        if isinstance(widget, ttk.Button) and widget['text'] == "Browse":
                            widget.config(state=tk.NORMAL)
        self.root.after(0, enable_browse_buttons)
        if self.cancellation_requested:
            self.log_message("Cancellation cleanup complete. Resources have been restored/terminated as applicable.", 'warning')
        else:
            self.log_message("Post-process cleanup complete.", 'info')
            
        self.cancellation_requested = False 
        self.forensic_instance = None
        self.current_volume_original_state = None
        self.sftp_client = None  # Add this to track active SFTP client


    def cancel_process(self):
        """Attempt to cancel the forensic process with forceful termination of SFTP."""
        if messagebox.askyesno("Confirm Cancel", 
                        "Are you sure you want to request cancellation of the forensic process? "
                        "If a process is running, it will attempt to stop and clean up."):
            messagebox.showwarning("WARNING!","CANCELLING THE PROCESS, THE TOOL MIGHT BE UNRESPONSIVE FOR A WHILE. DO NOT CLOSE THE TOOL!")
            self.log_message("CANCELLATION REQUESTED BY USER - Forcefully stopping processes...", 'warning')
            self.log_message("NOTE: CANCELLING PROCESS, THE TOOL MIGHT BE UNRESPONSIVE FOR A WHILE. DO NOT CLOSE THE TOOL!", "critical_warning")      
            
            self.cancellation_requested = True

            
            # Disable cancel button immediately
            self.cancel_btn.config(state=tk.DISABLED)
            
            # Show cancellation progress
            self.overall_progress.config(value=0)
            self.step_progress.config(value=0)
            
            def update_cancel_progress():
                if self.cancellation_requested:
                    current = self.step_progress['value']
                    if current < 100:
                        self.step_progress['value'] = current + 1
                        self.update_status(self.forensic_status_label, f"Cancelling... {int(current)}%", "warning")
                        self.root.after(50, update_cancel_progress)  # Update every 50ms
                    
            update_cancel_progress()

            def perform_cancellation():
                self.update_status(self.forensic_status_label, "Cleanup in progress...", "warning")
                try:
                    # Force close any active SFTP sessions
                    if hasattr(self, 'ssh_client') and self.ssh_client:
                        for attr in dir(self.ssh_client):
                            if 'sftp' in attr.lower():
                                try:
                                    sftp_obj = getattr(self.ssh_client, attr)
                                    if hasattr(sftp_obj, 'close'):
                                        sftp_obj.close()
                                except Exception:
                                    pass
                        
                        # Force close SSH transport
                        if self.ssh_client.get_transport():
                            self.ssh_client.get_transport().close()
                            self.ssh_client.close()
                        self.log_message("Forcefully closed SSH and SFTP connections.", 'warning')
                except Exception as e:
                    self.log_message(f"Error during forced SSH/SFTP shutdown: {e}", 'error')

                # Schedule cleanup
                self.root.after(1, self.cleanup_forensic_process)
                self.update_status(self.forensic_status_label,"Sucessfully cancelled forensic process.", "success")
            # Run cancellation in a separate thread
            threading.Thread(target=perform_cancellation, daemon=True).start()
            
            # Informational log based on start button state
            if self.start_btn['state'] != tk.DISABLED:
                self.log_message("Note: Start button was not disabled, suggesting the main process might have already concluded or failed. Cleanup will still be attempted if applicable.", "info")


    # ===================== AWS HELPER METHODS =====================
    def is_root_volume(self, volume_id, instance_id):
        """Check if the specified volume is the root volume of the instance."""
        try:
            ec2 = self.session.client('ec2')
            instance_desc = ec2.describe_instances(InstanceIds=[instance_id])
            root_device_name = instance_desc['Reservations'][0]['Instances'][0].get('RootDeviceName')
            if not root_device_name:
                return False

            volume_desc = ec2.describe_volumes(VolumeIds=[volume_id])
            for attachment in volume_desc['Volumes'][0].get('Attachments', []):
                if attachment['InstanceId'] == instance_id and attachment['Device'] == root_device_name:
                    return True
            return False
        except Exception as e:
            self.log_message(f"Error checking if volume {volume_id} is root for {instance_id}: {e}", 'error')
            return False 
            
    def stop_instance(self, instance_id):
        """Stop an EC2 instance and wait for it to be stopped."""
        try:
            ec2 = self.session.client('ec2')
            self.log_message(f"Sending stop command to instance {instance_id}...", 'info')
            ec2.stop_instances(InstanceIds=[instance_id])
            
            self.log_message(f"Waiting for instance {instance_id} to stop...", 'info')
            waiter = ec2.get_waiter('instance_stopped')
            waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 40}) 
            self.log_message(f"Instance {instance_id} stopped successfully.", 'success')
            return True
        except Exception as e:
            self.log_message(f"Error stopping instance {instance_id}: {e}", 'error')
            return False

    def start_instance(self, instance_id):
        """Start an EC2 instance and wait for it to be running."""
        try:
            ec2 = self.session.client('ec2')
            self.log_message(f"Sending start command to instance {instance_id}...", 'info')
            ec2.start_instances(InstanceIds=[instance_id])

            self.log_message(f"Waiting for instance {instance_id} to start running...", 'info')
            waiter = ec2.get_waiter('instance_running')
            waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 24}) 
            self.log_message(f"Instance {instance_id} started successfully.", 'success')
            return True
        except Exception as e:
            self.log_message(f"Error starting instance {instance_id}: {e}", 'error')
            return False

    def terminate_instance(self, instance_id):
        """Terminate an EC2 instance."""
        try:
            ec2 = self.session.client('ec2')
            self.log_message(f"Sending terminate command to instance {instance_id}...", 'info')
            ec2.terminate_instances(InstanceIds=[instance_id])
            
            self.log_message(f"Waiting for instance {instance_id} to terminate...", 'info')
            waiter = ec2.get_waiter('instance_terminated')
            waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 40}) 
            self.log_message(f"Instance {instance_id} terminated successfully.", 'success')
            return True
        except Exception as e:
            self.log_message(f"Error terminating instance {instance_id}: {e}", 'error')
            return False
            
    def create_new_instance(self, instance_name, template_instance_data, availability_zone=None, evidence_volume_size_gb=8):
        """
        Create a new forensic instance.
        The root volume of this forensic instance will be evidence_volume_size_gb + 10GB (min 30GB).
        """
        try:
            ec2 = self.session.client('ec2')
            self.log_message(f"Preparing to create forensic instance '{instance_name}' based on template instance '{template_instance_data.get('InstanceId', 'Unknown')}'.", "info")

            image_id = template_instance_data.get('ImageId')
            instance_type = template_instance_data.get('InstanceType')
            key_name = template_instance_data.get('KeyName')
            security_group_ids_from_template = template_instance_data.get('SecurityGroupIds', [])
            subnet_id_from_template = template_instance_data.get('SubnetId')

            if not image_id or image_id == 'N/A': raise ValueError("Template instance ImageId is missing or N/A.")
            if not instance_type or instance_type == 'N/A': raise ValueError("Template instance InstanceType is missing or N/A.")
            if not key_name or key_name == 'N/A': raise ValueError("Template instance KeyName is missing or N/A.")
            if not security_group_ids_from_template: raise ValueError("Template instance SecurityGroupIds are missing.")
            
            self.log_message(f"Using ImageId from template: {image_id}", "info")
            self.log_message(f"Using InstanceType from template: {instance_type}", "info")
            self.log_message(f"Using KeyName from template: {key_name}", "info")
            self.log_message(f"Using SecurityGroupIds from template: {security_group_ids_from_template}", "info")

            # Calculate forensic instance root volume size
            # Ensure it's at least 30GB, or evidence_volume_size + 10GB, whichever is larger.
            forensic_root_vol_size = int(evidence_volume_size_gb) + 10
            self.log_message(f"Target evidence volume size: {evidence_volume_size_gb}GB. Forensic instance root volume will be {forensic_root_vol_size}GB.", "info")


            run_instances_params = {
                'ImageId': image_id,
                'InstanceType': instance_type,
                'KeyName': key_name,
                'SecurityGroupIds': security_group_ids_from_template,
                'MinCount': 1,
                'MaxCount': 1,
                'TagSpecifications': [{
                    'ResourceType': 'instance',
                    'Tags': [{'Key': 'Name', 'Value': instance_name}, {'Key': 'Purpose', 'Value': 'ForensicAnalysisTool'}]
                },
                { 
                    'ResourceType': 'volume',
                    'Tags': [{'Key': 'Name', 'Value': f"{instance_name}-root"}, {'Key': 'Purpose', 'Value': 'ForensicAnalysisTool-RootVol'}]
                }],
                'BlockDeviceMappings': [{ 
                    'DeviceName': '/dev/sda1', 
                    'Ebs': {'VolumeSize': forensic_root_vol_size, 'DeleteOnTermination': True, 'VolumeType': 'gp3'} 
                }]
            }

            if subnet_id_from_template and subnet_id_from_template != 'N/A':
                run_instances_params['SubnetId'] = subnet_id_from_template
                self.log_message(f"Forensic instance will use SubnetId: {subnet_id_from_template} (from template instance). This defines the AZ.", "info")
            elif availability_zone and availability_zone != 'N/A':
                run_instances_params['Placement'] = {'AvailabilityZone': availability_zone}
                self.log_message(f"Forensic instance will use AvailabilityZone: {availability_zone} (from template instance, SubnetId was N/A or missing).", "info")
            else:
                raise ValueError("Template instance lacks both SubnetId and AvailabilityZone information.")

            response = ec2.run_instances(**run_instances_params)
            new_instance_id = response['Instances'][0]['InstanceId']
            self.log_message(f"Forensic instance {new_instance_id} launch initiated. Waiting for it to run...", 'info')
            
            waiter = ec2.get_waiter('instance_running')
            waiter.wait(InstanceIds=[new_instance_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 24}) 
            
            new_instance_info = ec2.describe_instances(InstanceIds=[new_instance_id])
            created_instance_data = new_instance_info['Reservations'][0]['Instances'][0]
            
            if 'PublicIpAddress' not in created_instance_data:
                self.log_message(f"Forensic instance {new_instance_id} launched without a public IP. Attempting to assign an Elastic IP.", "warning")
                try:
                    alloc_response = ec2.allocate_address(Domain='vpc')
                    elastic_ip = alloc_response['PublicIp']
                    ec2.associate_address(InstanceId=new_instance_id, AllocationId=alloc_response['AllocationId'])
                    self.log_message(f"Assigned Elastic IP {elastic_ip} to {new_instance_id}.", "success")
                    new_instance_info_updated = ec2.describe_instances(InstanceIds=[new_instance_id])
                    created_instance_data = new_instance_info_updated['Reservations'][0]['Instances'][0]
                    if 'PublicIpAddress' not in created_instance_data:
                         self.log_message(f"Still no Public IP for {new_instance_id} after EIP association attempt. Manual check needed.", "error")
                except Exception as eip_e:
                    self.log_message(f"Failed to assign or associate Elastic IP to {new_instance_id}: {eip_e}. SSH might fail.", "error")
            
            self.log_message(f"Forensic instance {new_instance_id} ({created_instance_data.get('PublicIpAddress', 'No Public IP')}) is running in AZ {created_instance_data.get('Placement', {}).get('AvailabilityZone')}.", 'success')
            return created_instance_data
        except Exception as e:
            self.log_message(f"Error creating new forensic instance '{instance_name}': {e}", 'error')
            import traceback
            self.log_message(traceback.format_exc(), "error")
            return None
            
    def move_volume_to_forensic(self, volume_id, original_instance_data, forensic_instance_data):
        """Detaches a volume from original instance and attaches it to the forensic instance."""
        ec2 = self.session.client('ec2')
        original_instance_id = original_instance_data['InstanceId']
        forensic_instance_id = forensic_instance_data['InstanceId']
        target_device_on_forensic = "/dev/sdf" # Suggested device for attachment

        try:
            self.log_message(f"Detaching volume {volume_id} from original instance {original_instance_id}...", 'info')
            ec2.detach_volume(VolumeId=volume_id, InstanceId=original_instance_id, Force=False) 
            waiter_available = ec2.get_waiter('volume_available')
            waiter_available.wait(VolumeIds=[volume_id], WaiterConfig={'Delay': 10, 'MaxAttempts': 18}) 
            self.log_message(f"Volume {volume_id} detached from {original_instance_id}.", 'success')

            self.log_message(f"Attaching volume {volume_id} to forensic instance {forensic_instance_id} as {target_device_on_forensic}...", 'info')
            ec2.attach_volume(VolumeId=volume_id, InstanceId=forensic_instance_id, Device=target_device_on_forensic)
            waiter_in_use = ec2.get_waiter('volume_in_use') 
            waiter_in_use.wait(VolumeIds=[volume_id], Filters=[{'Name':'attachment.instance-id', 'Values':[forensic_instance_id]}], WaiterConfig={'Delay': 10, 'MaxAttempts': 12}) 
            self.log_message(f"Volume {volume_id} attached to {forensic_instance_id} as {target_device_on_forensic}.", 'success')
            return target_device_on_forensic 
        except Exception as e:
            self.log_message(f"Error moving volume {volume_id}: {e}", 'error')
            try:
                vol_state = ec2.describe_volumes(VolumeIds=[volume_id])['Volumes'][0]['State']
                if vol_state == 'available': 
                    self.log_message(f"Attempting to reattach {volume_id} back to original instance {original_instance_id} due to error.", 'warning')
                    original_device = self.current_volume_original_state.get('original_device_name', '/dev/xvdf') 
                    ec2.attach_volume(VolumeId=volume_id, InstanceId=original_instance_id, Device=original_device)
                    waiter_in_use = ec2.get_waiter('volume_in_use') # Re-assign waiter for this specific check
                    waiter_in_use.wait(VolumeIds=[volume_id], Filters=[{'Name':'attachment.instance-id', 'Values':[original_instance_id]}])
                    self.log_message(f"Volume {volume_id} reattached to original instance.", 'info')
            except Exception as reattach_err:
                self.log_message(f"Failed to automatically reattach {volume_id} to original instance: {reattach_err}. Manual check needed.", 'error')
            return None

    def reattach_volume_to_original(self, volume_id, original_instance_data, forensic_instance_data_nullable, original_device_name):
        """Detaches volume from forensic (if attached) and reattaches to original."""
        ec2 = self.session.client('ec2')
        original_instance_id = original_instance_data['InstanceId']
        
        try:
            vol_description = ec2.describe_volumes(VolumeIds=[volume_id])['Volumes'][0]
            current_attachments = vol_description.get('Attachments', [])
            is_attached_to_forensic = False

            if forensic_instance_data_nullable and forensic_instance_data_nullable.get('InstanceId'):
                forensic_id = forensic_instance_data_nullable['InstanceId']
                for att in current_attachments:
                    if att.get('InstanceId') == forensic_id:
                        is_attached_to_forensic = True
                        self.log_message(f"Volume {volume_id} is attached to forensic instance {forensic_id}. Detaching...", 'info')
                        ec2.detach_volume(VolumeId=volume_id, InstanceId=forensic_id, Force=False) 
                        waiter_available = ec2.get_waiter('volume_available')
                        waiter_available.wait(VolumeIds=[volume_id], WaiterConfig={'Delay': 10, 'MaxAttempts': 18})
                        self.log_message(f"Volume {volume_id} detached from forensic instance.", 'success')
                        break # Important: exit loop once detached
            
            # Re-fetch volume description to get the latest state after potential detach
            vol_description_after_detach = ec2.describe_volumes(VolumeIds=[volume_id])['Volumes'][0]

            if vol_description_after_detach['State'] != 'available':
                self.log_message(f"Volume {volume_id} not 'available' (state: {vol_description_after_detach['State']}) before attaching to original. Waiting...", 'warning')
                waiter_available_retry = ec2.get_waiter('volume_available')
                try:
                    waiter_available_retry.wait(VolumeIds=[volume_id], WaiterConfig={'Delay':10, 'MaxAttempts':12}) # Wait up to 2 mins
                    self.log_message(f"Volume {volume_id} is now available.", 'info')
                except Exception as e_wait_final:
                     self.log_message(f"Volume {volume_id} did not become available for reattachment: {e_wait_final}. Reattachment might fail.", 'error')
                     # Optionally, could raise an error here or attempt attachment anyway

            self.log_message(f"Reattaching volume {volume_id} to original instance {original_instance_id} as {original_device_name}...", 'info')
            ec2.attach_volume(VolumeId=volume_id, InstanceId=original_instance_id, Device=original_device_name)

            waiter_in_use = ec2.get_waiter('volume_in_use')
            waiter_in_use.wait(VolumeIds=[volume_id], Filters=[{'Name':'attachment.instance-id', 'Values':[original_instance_id]}], WaiterConfig={'Delay': 10, 'MaxAttempts': 12})
            self.log_message(f"Volume {volume_id} reattached to {original_instance_id} as {original_device_name}.", 'success')
            return True
        except Exception as e:
            self.log_message(f"Error reattaching volume {volume_id} to original instance {original_instance_id}: {e}", 'error')
            return False

    def connect_with_retry(self, hostname, username, key_filename, max_retries=10, retry_interval=20):
        """Connects to an EC2 instance via SSH with retry logic and keepalive."""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            key = paramiko.RSAKey.from_private_key_file(key_filename)
        except paramiko.PasswordRequiredException:
            self.log_message(f"SSH key file {key_filename} is encrypted and requires a passphrase. This tool does not support passphrase-protected keys.", "error")
            return None
        except Exception as e_key:
            self.log_message(f"Error loading SSH key {key_filename}: {e_key}", "error")
            return None


        for attempt in range(max_retries):
            if self.cancellation_requested:
                self.log_message("SSH connection cancelled by user.", "warning")
                return None
            try:
                self.log_message(f"SSH connection attempt {attempt + 1}/{max_retries} to {username}@{hostname}...", 'info')
                ssh.connect(hostname=hostname, username=username, pkey=key, timeout=30, look_for_keys=False)
                
                transport = ssh.get_transport()
                if transport and transport.is_active():
                    transport.set_keepalive(60) 
                    self.log_message("SSH connection established successfully. Keepalive set to 60s.", 'success')
                else: # Should not happen if connect succeeded
                    self.log_message("SSH connection established, but could not get active transport to set keepalive.", 'warning')
                return ssh
            except paramiko.AuthenticationException as auth_e:
                self.log_message(f"SSH Authentication failed: {auth_e}. Check key, username, and instance SSH configuration.", 'error')
                break 
            except (paramiko.SSHException, TimeoutError, ConnectionRefusedError, OSError) as e: 
                self.log_message(f"SSH connection failed (Attempt {attempt+1}): {e}", 'warning')
                if attempt < max_retries - 1:
                    self.log_message(f"Retrying in {retry_interval} seconds...", 'info')
                    time.sleep(retry_interval)
                else:
                    self.log_message("Failed to establish SSH connection after multiple attempts.", 'error')
                    break 
        return None
            
    def install_dc3dd_and_gpg(self):
        """Install forensic tools on the remote instance"""
        commands_to_run = [ 
            "sudo apt-get update -y",
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y dc3dd gnupg" 
        ]
        for current_command in commands_to_run: 
            if self.cancellation_requested: return
            self.log_message(f"Executing on forensic instance: {current_command}", 'info', timestamp=False)
            stdin, stdout, stderr = self.ssh_client.exec_command(current_command, timeout=300) 
            exit_status = stdout.channel.recv_exit_status() 

            out = stdout.read().decode(errors='ignore') 
            err = stderr.read().decode(errors='ignore') 
            if out.strip(): self.log_message(f"Output:\n{out.strip()}", 'info', timestamp=False)
            if err.strip(): self.log_message(f"Error/Warning Output:\n{err.strip()}", 'warning' if exit_status == 0 else 'error', timestamp=False)
            
            if exit_status != 0:
                raise Exception(f"Command '{current_command}' failed with exit status {exit_status}")
        self.log_message("Evidence Gathering tools (dc3dd, gpg) installation completed.", 'success')

    def create_working_directory(self):
        """Create working directory on remote instance"""
        working_dir = '/tmp/forensic_work' 
        command_mkdir = f'mkdir -p {working_dir} && chmod 700 {working_dir}' 
        stdin, stdout, stderr = self.ssh_client.exec_command(command_mkdir)
        exit_status = stdout.channel.recv_exit_status()
        err = stderr.read().decode(errors='ignore').strip() 
        if exit_status != 0:
            self.log_message(f"Error creating working directory {working_dir}: {err}", 'error')
            return None
        self.log_message(f"Working directory {working_dir} created/ensured on forensic instance.", 'info')
        return working_dir

    def run_imaging_and_encryption_pipeline(self, volume_id_to_image, working_dir, passphrase):
        """
        Runs a piped command to image, hash, and encrypt in one go.
        sudo dc3dd | tee >(sha256sum > hash.txt) | gpg > image.gpg
        """
        # 1. Discover device path
        actual_device_path_for_dc3dd = None
        lsblk_command = 'lsblk -o name,size -lnd'
        max_lsblk_retries = 3
        lsblk_retry_delay_seconds = 10

        self.log_message(f"Attempting to identify device for imaging volume '{volume_id_to_image}' using '{lsblk_command}' with retries...", 'info')
        for attempt in range(max_lsblk_retries):
            if self.cancellation_requested: raise InterruptedError("Device discovery cancelled by user.")
            
            self.log_message(f"lsblk attempt {attempt + 1}/{max_lsblk_retries}...", 'info')
            stdin, stdout, stderr_lsblk = self.ssh_client.exec_command(lsblk_command, timeout=30)
            exit_status_lsblk = stdout.channel.recv_exit_status()
            lsblk_output_raw = stdout.read().decode(errors='ignore').strip()

            if exit_status_lsblk == 0 and lsblk_output_raw and len(lsblk_output_raw.splitlines()) >= 2:
                device_line_to_parse = lsblk_output_raw.splitlines()[-1]
                device_name_short = device_line_to_parse.split(" ")[0].strip()
                if device_name_short:
                    actual_device_path_for_dc3dd = f"/dev/{device_name_short}"
                    break
            
            if not actual_device_path_for_dc3dd and attempt < max_lsblk_retries - 1:
                self.log_message(f"Device not identified. Retrying lsblk in {lsblk_retry_delay_seconds} seconds...", 'info')
                time.sleep(lsblk_retry_delay_seconds)

        if not actual_device_path_for_dc3dd:
            raise Exception("Device path for imaging could not be determined after multiple retries.")
        
        # 2. Define file paths and construct the pipeline command
        encrypted_image_path = f"{working_dir}/{volume_id_to_image}.img.gpg"
        raw_hash_output_path = f"{working_dir}/{volume_id_to_image}.sha256"

        dc3dd_part = f"sudo dc3dd if={actual_device_path_for_dc3dd} verb=on"
        tee_part = f"tee >(sha256sum > {raw_hash_output_path})"
        gpg_part = (f"gpg --batch --yes --pinentry-mode loopback --passphrase '{passphrase}' "
                    f"--symmetric --cipher-algo AES256 -o {encrypted_image_path}")

        # Use bash -c 'set -o pipefail; ...' to ensure failure in any part of the pipe fails the whole command
        pipeline_command_str = f"bash -c 'set -o pipefail; {dc3dd_part} | {tee_part} | {gpg_part}'"

        self.log_message(f"Executing pipeline: {pipeline_command_str.replace(passphrase, '********')}", 'info', timestamp=False)

        # 3. Execute and monitor the command
        stdin, stdout, stderr = self.ssh_client.exec_command(pipeline_command_str, timeout=21600) # 6 hour timeout
        channel = stdout.channel
        channel.setblocking(0)

        last_progress_line = None
        last_progress_display_time = 0
        progress_log_interval = 3.0

        self.log_message("--- Imaging & Encryption process started, monitoring stderr ---", "info", timestamp=True)

        while not channel.exit_status_ready():
            if self.cancellation_requested:
                raise InterruptedError("Process cancelled by user request.")

            try:
                if channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(4096).decode(errors='ignore')
                    for sub_line_raw in chunk.replace('\r', '\n').splitlines():
                        sub_line = sub_line_raw.strip()
                        if not sub_line: continue

                        is_progress_line = ("%" in sub_line and "copied" in sub_line)
                        if is_progress_line:
                            last_progress_line = sub_line
                            try:
                                percent_str = sub_line.split('%')[0].split('(')[-1].strip()
                                self.root.after(0, lambda p=int(percent_str): self.step_progress.config(value=p))
                            except (ValueError, IndexError): pass
                        else:
                            if last_progress_line:
                                self.log_message(last_progress_line, 'info', timestamp=False)
                                last_progress_line = None
                            self.log_message(sub_line, 'info', timestamp=False)
                
                if last_progress_line and (time.time() - last_progress_display_time > progress_log_interval):
                    self.log_message(last_progress_line, 'info', timestamp=False)
                    last_progress_display_time = time.time()
                    last_progress_line = None
                
                if not channel.recv_stderr_ready(): time.sleep(0.1)

            except BlockingIOError: time.sleep(0.1)
            except Exception as e_stderr_read:
                self.log_message(f"Exception while reading pipeline streams: {e_stderr_read}", "error")
                time.sleep(0.5)
        
        if last_progress_line: self.log_message(last_progress_line, 'info', timestamp=False)

        exit_status = channel.recv_exit_status()
        self.log_message(f"--- Process completed exit_status: {exit_status} ---", "info", timestamp=True)
        
        if exit_status != 0:
            error_output = stderr.read().decode(errors='ignore').strip()
            self.log_message(f"Imaging/Encryption process failed. Stderr: {error_output}", 'error')
            raise Exception(f"Imaging/Encryption process failed with exit status {exit_status}.")

        # 4. Retrieve the calculated hash
        raw_hash = self.get_remote_file_content(raw_hash_output_path)
        if raw_hash and len(raw_hash.split()) > 0:
            raw_hash_on_forensic = raw_hash.split()[0]
        else:
            self.log_message("Failed to retrieve raw stream hash from remote file.", "error")
            raw_hash_on_forensic = "N/A_Hash_File_Read_Error"

        return {
            "raw_hash": raw_hash_on_forensic,
            "encrypted_image_path": encrypted_image_path,
            "raw_hash_output_path": raw_hash_output_path
        }


    def calculate_sha256_remote(self, remote_file_path):
        """Calculate SHA256 hash of a file on the remote instance."""
        if self.cancellation_requested:
            self.log_message(f"Remote SHA256 calculation for {remote_file_path} cancelled before start.", "warning")
            raise InterruptedError("Remote SHA256 calculation cancelled.")

        self.log_message(f"Calculating SHA256 for remote file: {remote_file_path}", "info")
        command = f"sha256sum {remote_file_path}"
        stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=7200) # Increased timeout for potentially large files
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode(errors='ignore').strip()
        error = stderr.read().decode(errors='ignore').strip()

        if exit_status == 0 and output:
            hash_val = output.split()[0]
            if len(hash_val) == 64:
                self.log_message(f"SHA256 for {remote_file_path}: {hash_val}", "success")
                return hash_val
            else:
                self.log_message(f"sha256sum for {remote_file_path} produced invalid hash format: {output}", 'error')
                return f"N/A_Invalid_Hash_Format_For_{os.path.basename(remote_file_path)}"
        else:
            self.log_message(f"Error calculating SHA256 for {remote_file_path} on remote. Exit: {exit_status}, Stderr: {error}, Stdout: {output}", 'error')
            return f"N/A_Calculation_Error_For_{os.path.basename(remote_file_path)}"

    def calculate_sha256_local(self, local_file_path, progress_widget=None):
        """Calculate SHA256 hash of a local file, with optional progress updates."""
        if self.cancellation_requested:
            self.log_message(f"Local SHA256 calculation for {local_file_path} cancelled before start.", "warning")
            raise InterruptedError("Local SHA256 calculation cancelled.")
            
        if not local_file_path or not os.path.exists(local_file_path):
            self.log_message(f"Local file not found for hashing: {local_file_path}", "error")
            return None
        
        sha256_hash = hashlib.sha256()
        try:
            file_size = os.path.getsize(local_file_path)
            processed_bytes = 0
            last_logged_percent = -1

            if progress_widget:
                self.root.after(0, lambda: progress_widget.config(value=0, maximum=100))

            with open(local_file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096 * 1024), b""): # Read in 4MB chunks
                    if self.cancellation_requested: # Check inside the loop
                        self.log_message(f"Local SHA256 calculation for {local_file_path} cancelled during processing.", "warning")
                        raise InterruptedError("Local SHA256 calculation cancelled.")
                    sha256_hash.update(byte_block)
                    processed_bytes += len(byte_block)
                    
                    if file_size > 0:
                        percent_done = (processed_bytes / file_size) * 100
                        if progress_widget:
                            self.root.after(0, lambda p=percent_done: progress_widget.config(value=p))
                        
                        # Log progress every ~10%
                        if int(percent_done) // 10 > last_logged_percent // 10 :
                            self.log_message(f"Local hashing of {os.path.basename(local_file_path)}: {percent_done:.1f}% complete...", "info", timestamp=True, newline=True)
                            last_logged_percent = int(percent_done)
            
            if progress_widget:
                 self.root.after(0, lambda: progress_widget.config(value=100))
            self.log_message(f"Local SHA256 calculation for {os.path.basename(local_file_path)} complete.", "success")
            return sha256_hash.hexdigest()

        except InterruptedError: # Propagate if cancelled inside loop
            raise 
        except Exception as e:
            self.log_message(f"Error hashing local file {local_file_path}: {e}", "error")
            if progress_widget:
                 self.root.after(0, lambda: progress_widget.config(value=0))
            return f"N/A_Local_Hash_Error_For_{os.path.basename(local_file_path)}"
            
    def calculate_sha256_local_parallel(self, file_paths):
        """
        Calculate SHA256 hashes for a list of local files in parallel using multiprocessing.
        Logs results to the GUI.
        """
        def hash_file(path):
            try:
                sha256_hash = hashlib.sha256()
                with open(path, "rb") as f:
                    for byte_block in iter(lambda: f.read(4096 * 1024), b""):
                        sha256_hash.update(byte_block)
                return (path, sha256_hash.hexdigest())
            except Exception as e:
                return (path, f"ERROR: {e}")

        self.log_message(f"Starting parallel SHA256 hashing for {len(file_paths)} files...", "info")
        with multiprocessing.Pool(processes=min(multiprocessing.cpu_count(), len(file_paths))) as pool:
            results = pool.map(hash_file, file_paths)
        for path, hashval in results:
            self.log_message(f"SHA256 for {os.path.basename(path)}: {hashval}", "success" if not hashval.startswith("ERROR") else "error")
        return dict(results)

    def gpg_encrypt_symmetric(self, input_file_path, passphrase, output_file_path):
        """Encrypt the forensic image using GPG symmetrically."""
        # Validate passphrase before proceeding
        if not passphrase or not passphrase.strip():
            self.log_message("GPG encryption failed: Passphrase is empty or only whitespace.", "error")
            raise Exception("GPG encryption failed: Passphrase is empty or only whitespace.")
        if any(c in passphrase for c in ["'", '"', "\n", "\r"]):
            self.log_message("GPG encryption failed: Passphrase contains invalid characters (quotes or newlines).", "error")
            raise Exception("GPG encryption failed: Passphrase contains invalid characters (quotes or newlines).")
        try:
            passphrase.encode("ascii")
        except Exception:
            self.log_message("GPG encryption failed: Passphrase must contain only ASCII characters.", "error")
            raise Exception("GPG encryption failed: Passphrase must contain only ASCII characters.")

        if self.cancellation_requested:
            self.log_message(f"GPG encryption for {input_file_path} cancelled before start.", "warning")
            raise InterruptedError("GPG encryption cancelled.")

        command = (f"gpg --batch --yes --pinentry-mode loopback --passphrase '{passphrase}' "
                   f"--symmetric --cipher-algo AES256 "
                   f"-o {output_file_path} {input_file_path}")
        self.log_message(f"Executing GPG encryption: gpg ... -o {output_file_path} {input_file_path}", 'info', timestamp=False) 
        
        stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=7200) 
        exit_status = stdout.channel.recv_exit_status()
        
        out = stdout.read().decode(errors='ignore').strip()
        err = stderr.read().decode(errors='ignore').strip()

        if out: self.log_message(f"GPG stdout: {out}", 'info', timestamp=False)
        if err: self.log_message(f"GPG stderr: {err}", 'warning' if "warning" in err.lower() else 'info', timestamp=False) 

        if exit_status != 0:
            raise Exception(f"GPG encryption failed with exit status {exit_status}. Stderr: {err}")
        self.log_message(f"GPG encryption successful: {output_file_path}", 'success')

    def get_remote_file_content(self, remote_file_path):
        """Fetch content of a small text file from remote."""
        sftp = None
        try:
            sftp = self.ssh_client.open_sftp()
            with sftp.file(remote_file_path, 'r') as f:
                content = f.read().decode(errors='ignore')
            return content
        except Exception as e:
            self.log_message(f"Exception getting content of {remote_file_path} via SFTP: {e} (SFTP Error: {type(e).__name__})", "error")
            return None
        finally:
            if sftp: sftp.close()


    def download_evidences_sftp(self, remote_to_local_filenames_map, volume_id_for_subdir):
        """Download specified evidence files from the forensic instance using SFTP."""
        if self.cancellation_requested:
            self.log_message("Evidence download cancelled before start.", "warning")
            raise InterruptedError("Evidence download cancelled.")

        downloaded_paths_map = {}
        local_evidence_subdir = os.path.join(self.output_dir, f"evidence_{volume_id_for_subdir}")
        os.makedirs(local_evidence_subdir, exist_ok=True)

        sftp_main = None # Main SFTP client for the download loop
        try:
            sftp_main = self.ssh_client.open_sftp() 
            self.log_message(f"SFTP session opened for downloading to {local_evidence_subdir}.", 'info')

            for remote_path, local_filename_only in remote_to_local_filenames_map.items():
                if self.cancellation_requested: # Check before each file
                    raise InterruptedError("Download cancelled by user during file loop.")
                
                local_full_path = os.path.join(local_evidence_subdir, local_filename_only)
                self.log_message(f"Starting download: {remote_path} -> {local_full_path}", 'info')
                
                try:
                    file_size = sftp_main.stat(remote_path).st_size
                    if file_size < 1024:
                        self.log_message(f"File size: {file_size} bytes", "info")
                    elif file_size < 1024*1024:
                        self.log_message(f"File size: {file_size/1024:.2f} KB", "info")
                    else:
                        self.log_message(f"File size: {file_size/(1024*1024):.2f} MB", "info")
                
                    self.root.after(0, lambda: self.step_progress.config(value=0, maximum=100))
                    
                    class ProgressTracker:
                        def __init__(self, total_b, gui_root, progress_bar_widget, log_func, file_display_name, cancellation_flag_getter):
                            self.transferred = 0
                            self.total_bytes = total_b
                            self.start_time = time.time()
                            self.last_update_time = 0
                            self.gui_root = gui_root
                            self.progress_bar = progress_bar_widget
                            self.log_func = log_func
                            self.file_display_name = file_display_name
                            self.last_logged_percent = -1
                            self.get_cancellation_flag = cancellation_flag_getter


                        def sftp_callback(self, bytes_so_far, _total_bytes_unused): 
                            if self.get_cancellation_flag():
                                self.log_func(f"SFTP download for {self.file_display_name} detected cancellation in callback.", "warning", timestamp=True)
                                return 

                            self.transferred = bytes_so_far
                            current_time = time.time()
                            
                            percent = (self.transferred / self.total_bytes) * 100 if self.total_bytes > 0 else 0
                            
                            if current_time - self.last_update_time > 0.1 or self.transferred == self.total_bytes : 
                                self.gui_root.after(0, lambda p=percent: self.progress_bar.config(value=p))
                                self.last_update_time = current_time

                            if int(percent) // 5 > self.last_logged_percent // 5 or self.transferred == self.total_bytes:
                                elapsed = current_time - self.start_time
                                speed = self.transferred / elapsed if elapsed > 0 else 0
                                speed_mbps = (speed * 8) / (1024 * 1024) 
                                self.log_func(f"\rDL {self.file_display_name}: {percent:.1f}% ({self.transferred/(1024*1024):.2f}/{self.total_bytes/(1024*1024):.2f} MB) @ {speed_mbps:.2f} Mbps\n", 'info', timestamp=False, newline=False)
                                self.last_logged_percent = int(percent)
                                if self.transferred == self.total_bytes:
                                     self.log_func("", 'info', timestamp=False, newline=True) 
                    
                    tracker = ProgressTracker(file_size, self.root, self.step_progress, self.log_message, local_filename_only, lambda: self.cancellation_requested)
                    sftp_main.get(remote_path, local_full_path, callback=tracker.sftp_callback) 
                    
                    if self.cancellation_requested: # Check immediately after sftp.get()
                        raise InterruptedError(f"Download of {local_filename_only} cancelled after sftp.get call.")

                    self.log_message("", 'info', timestamp=False, newline=True) 

                    if os.path.getsize(local_full_path) == file_size:
                        self.log_message(f"Successfully downloaded: {local_full_path}", 'success')
                        downloaded_paths_map[remote_path] = local_full_path
                    else:
                        self.log_message(f"Download size mismatch for {local_full_path}. Remote: {file_size}, Local: {os.path.getsize(local_full_path)}", 'error')
                except InterruptedError: # Propagate if raised by callback or check
                    raise
                except Exception as e_file_dl:
                    self.log_message(f"\nError downloading {remote_path}: {e_file_dl} (SFTP Error: {type(e_file_dl).__name__})", 'error')

            return downloaded_paths_map
        except InterruptedError: # Propagate if raised by initial check or loop
            raise
        except Exception as e:
            self.log_message(f"SFTP Download process failed: {e} (SFTP Error: {type(e).__name__})", 'error')
            return downloaded_paths_map 
        finally:
            if sftp_main: # Close the main SFTP client
                sftp_main.close()
                self.log_message("SFTP session closed.", 'info')
            self.root.after(0, lambda: self.step_progress.config(value=0))
            
    def export_coc_logs(self, investigator, source_instance_data, forensic_instance_data, 
                        volume_id, key_path_name, passphrase_commitment, hashes, 
                        downloaded_files_map):
        """Generate comprehensive Chain of Custody documentation."""
        if self.cancellation_requested:
            self.log_message("Chain of Custody generation cancelled before start.", "warning")
            raise InterruptedError("Chain of Custody generation cancelled.")
            
        try:
            if not self.output_dir:
                self.log_message("Output directory not set for CoC.", 'error')
                return None

            coc_output_dir = os.path.join(self.output_dir, f"coc_{volume_id}")
            os.makedirs(coc_output_dir, exist_ok=True)

            timestamp_long = datetime.now().isoformat()
            timestamp_short = datetime.now().strftime("%Y%m%d_%H%M%S")
            investigator_sanitized = "".join(c for c in investigator.split("@")[0] if c.isalnum())[:15]
            case_id = f"AWS-{volume_id}-{investigator_sanitized}-{timestamp_short}"

            sts = self.session.client('sts')
            account_info = sts.get_caller_identity()
            
            local_encrypted_image_path = None
            for remote_p, local_p in downloaded_files_map.items():
                if remote_p.endswith('.img.gpg'):
                    local_encrypted_image_path = local_p
                    break
            
            encrypted_size_local = os.path.getsize(local_encrypted_image_path) if local_encrypted_image_path and os.path.exists(local_encrypted_image_path) else "N/A"

            hash_verification_notes = []
            hash_match_status = "Mismatch/Error" 
            if hashes.get("encrypted_on_forensic") and hashes.get("downloaded_encrypted_local"):
                # Ensure both are strings for comparison, handle N/A cases
                h_forensic = str(hashes["encrypted_on_forensic"])
                h_local = str(hashes["downloaded_encrypted_local"])
                if "N/A" not in h_forensic and "N/A" not in h_local:
                    if h_forensic == h_local:
                        hash_verification_notes.append("SUCCESS: Encrypted image hash matches between forensic instance and local download.")
                        hash_match_status = "Verified"
                        self.log_message("The Hashes is Sucessfully Verified", "critical_warning")
                    else:
                        hash_verification_notes.append("ERROR: Encrypted image hash MISMATCH between forensic instance and local download.")
                else:
                    hash_verification_notes.append("WARNING: One or both encrypted hashes (forensic/local) are marked N/A, direct comparison not possible.")
            else:
                hash_verification_notes.append("WARNING: Could not verify encrypted image hash between forensic and local (one or both hashes missing entirely).")


            json_log_data = {
                "caseInformation": {
                    "caseID": case_id,
                    "investigator": investigator,
                    "collectionTimestamp": timestamp_long,
                    "awsAccountID": account_info.get("Account"),
                    "awsUserID": account_info.get("UserId"),
                    "awsRegion": self.session.region_name,
                },
                "sourceEvidence": {
                    "instanceID": source_instance_data['InstanceId'],
                    "instanceName": source_instance_data.get('Name', "Unnamed"),
                    "volumeID": volume_id,
                    "originalDeviceName": self.current_volume_original_state.get('original_device_name', 'N/A') if self.current_volume_original_state else 'N/A',
                },
                "forensicEnvironment": {
                    "forensicInstanceID": forensic_instance_data.get('InstanceId', "N/A"),
                    "forensicInstanceIP": forensic_instance_data.get('PublicIpAddress', "N/A"),
                    "sshKeyUsed": key_path_name,
                    "passphraseCommitment_SHA256": passphrase_commitment,
                },
                "evidenceAcquisition": {
                    "rawImageSHA256_OnForensic": hashes.get("raw_on_forensic"), # This now comes from sha256sum
                    "encryptedImageSHA256_OnForensic": hashes.get("encrypted_on_forensic"),
                    "encryptedImageSHA256_Local": hashes.get("downloaded_encrypted_local"),
                    "encryptedImageLocalPath": local_encrypted_image_path,
                    "encryptedImageLocalSizeBytes": encrypted_size_local,
                    "hashVerificationNotes": hash_verification_notes,
                },
                "tooling": {
                    "imagingTool": "dc3dd (version assumed 7.x)", 
                    "encryptionTool": "gpg (version assumed 2.x, AES256)",
                }
            }

            json_path = os.path.join(coc_output_dir, f"{case_id}_coc.json")
            with open(json_path, 'w') as f:
                json.dump(json_log_data, f, indent=4)

            self.coc_data.append({
                "case_id": case_id, "volume_id": volume_id, "status": "Collected", "timestamp": timestamp_long
            })
            self.integrity_data.append({
                "volume_id": volume_id,
                "hash_match": hash_match_status, 
                "encrypted": "Yes",
                "raw_hash": hashes.get("raw_on_forensic", "N/A"),
                "encrypted_hash": hashes.get("encrypted_on_forensic", "N/A"),
                "encrypted_local_hash": hashes.get("downloaded_encrypted_local", "N/A")  
            })
            self.report_data.append((case_id, volume_id, timestamp_long))
            self.root.after(0, self.update_results_tables)

            return {"case_id": case_id, "json_log_path": json_path}

        except InterruptedError: # Propagate if raised by initial check
            raise
        except Exception as e:
            self.log_message(f"Chain of Custody documentation generation failed: {e}", 'error')
            import traceback
            self.log_message(traceback.format_exc(), "error")
            return None
