# main.py
import tkinter as tk
from gui import IPAMApp

def main():
    """ Initialize the IPAM GUI Application """
    root = tk.Tk()
    app = IPAMApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
