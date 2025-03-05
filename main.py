import tkinter as tk
from gui import CloudTrailLogExplorerGUI

def main():
    root = tk.Tk()
    app = CloudTrailLogExplorerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 