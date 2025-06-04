import tkinter as tk
from gui.forensicgui import ForensicGUI
import sys

if __name__ == "__main__":
  import multiprocessing
  multiprocessing.freeze_support()
  root = tk.Tk()
  app = ForensicGUI(root)
  root.mainloop()


