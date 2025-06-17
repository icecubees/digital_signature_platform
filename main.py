# main.py
import tkinter as tk
from ui.interface import SignatureApp

if __name__ == "__main__":
    root = tk.Tk()
    app = SignatureApp(root)
    root.mainloop()
