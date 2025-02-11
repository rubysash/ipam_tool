# gui.py
import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as tb
from search import SearchHandler
from db import DatabaseManager
from utils import Utils
import config
import ipaddress

class IPAMApp:
    """ Main IPAM GUI Application """

    def __init__(self, root):
        """ Initialize the GUI layout """
        self.root = root
        self.root.title(f"IP Address Management (IPAM) v{config.VERSION}")
        self.root.geometry("800x600")  # Increased for better readability with larger fonts
        
        # Initialize style before setting any widget configurations
        self.style = tb.Style(config.THEME)
        
        # Configure base styles for different widget types
        self.style.configure("TLabel", font=config.LABEL_FONT)
        self.style.configure("TEntry", font=config.ENTRY_FONT)

        # Configure button styles - both default and colored variants
        button_settings = {
            "font": config.BUTTON_FONT,
            "padding": config.WIDGET_PADDING
        }
        self.style.configure("TButton", **button_settings)
        self.style.configure("warning.TButton", **button_settings)
        self.style.configure("danger.TButton", **button_settings)
        self.style.configure("success.TButton", **button_settings)
        
        # Configure Treeview specific styles
        self.style.configure("Treeview", 
                            font=config.TREEVIEW_FONT,
                            rowheight=int(config.TREEVIEW_FONT[1] * 1.6))
        self.style.configure("Treeview.Heading", 
                            font=config.TREEVIEW_FONT,
                            padding=config.WIDGET_PADDING)
        
        # Configure message styles
        self.style.configure("Flash.TLabel", 
                            font=config.MESSAGE_FONT,
                            padding=config.WIDGET_PADDING)
        
        # Configure heading styles
        self.style.configure("Heading.TLabel", 
                            font=config.HEADING_FONT,
                            padding=config.WIDGET_PADDING)
        
        # Initialize database and search handlers
        self.db = DatabaseManager(config.DATABASE_PATH)
        self.search_handler = SearchHandler(self.perform_search)
        
        # Initialize sorting variables
        self.sort_column = None
        self.sort_reverse = False
        
        # Setup UI components
        self.setup_frames()
        self.setup_widgets()

    def setup_frames(self):
        """ Create and organize frames """
        self.frame0 = ttk.Frame(self.root)
        self.frame0.pack(fill="x", pady=5)

        self.frame1 = ttk.Frame(self.root)
        self.frame1.pack(fill="x", pady=5)

        self.frame2 = ttk.Frame(self.root)
        self.frame2.pack(fill="both", expand=True, pady=5)

        self.frame3 = ttk.Frame(self.root)
        self.frame3.pack(fill="x", pady=5)

    def setup_widgets(self):
        """ Create search bar, messages, treeview, and modify button """
        # Search Label and Entry
        search_label = ttk.Label(self.frame0, text="Search:", font=config.LABEL_FONT)
        search_label.pack(side="left", padx=config.WIDGET_PADDING)
        
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(
            self.frame0, 
            textvariable=self.search_var,
            font=config.ENTRY_FONT
        )
        self.search_entry.pack(
            fill="x", 
            expand=True, 
            padx=config.WIDGET_PADDING, 
            pady=config.WIDGET_PADDING
        )
        self.search_entry.bind("<KeyRelease>", self.on_search_input)

        # Flash Message
        self.flash_message = ttk.Label(
            self.frame1, 
            text="", 
            foreground="red",
            font=config.MESSAGE_FONT,
            wraplength=550  # Prevent text truncation
        )
        self.flash_message.pack(pady=config.WIDGET_PADDING)

        # CIDR Blocks Label
        header_label = ttk.Label(
            self.frame2, 
            text="Assigned CIDR Blocks",
            font=config.HEADING_FONT
        )
        header_label.pack(
            anchor="w", 
            padx=config.WIDGET_PADDING, 
            pady=config.WIDGET_PADDING
        )

        # Treeview Setup
        tree_frame = ttk.Frame(self.frame2)
        tree_frame.pack(fill="both", expand=True, pady=config.WIDGET_PADDING)

        # Configure Treeview with specific font
        style = ttk.Style()
        style.configure(
            "Treeview",
            font=config.TREEVIEW_FONT,
            rowheight=int(config.TREEVIEW_FONT[1] * 1.6)  # Scale row height with font
        )
        style.configure(
            "Treeview.Heading",
            font=config.TREEVIEW_FONT
        )

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("ID", "CIDR", "Note"),
            show="headings",
            style="Treeview"
        )
        
        # Add double-click binding
        self.tree.bind("<Double-1>", self.on_double_click)

        # Scrollbar
        y_scroll = ttk.Scrollbar(
            tree_frame, 
            orient="vertical", 
            command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=y_scroll.set)
        y_scroll.pack(side="right", fill="y")

        # Configure columns
        self.tree.heading("ID", text="ID")
        self.tree.heading("CIDR", text="CIDR", 
                        command=lambda: self.sort_treeview("CIDR"))
        self.tree.heading("Note", text="Note", 
                        command=lambda: self.sort_treeview("Note"))

        self.tree.column("ID", width=0, stretch=False)
        self.tree.column("CIDR", anchor="center", minwidth=150)
        self.tree.column("Note", anchor="center", minwidth=200)

        self.tree.pack(fill="both", expand=True)

        # Initialize default sort
        self.sort_column = "CIDR"
        self.sort_reverse = True

        # Button and Subnet Size Selection Frame
        btn_frame = ttk.Frame(self.frame3)
        btn_frame.pack(pady=config.FRAME_PADDING)

        # Add button
        ttk.Button(
            btn_frame,
            text="Add",
            command=lambda: self.open_modify_popup(None, is_new_record=True),
            style="success.TButton"
        ).pack(side="left", padx=5)

        # Modify button
        ttk.Button(
            btn_frame,
            text="Modify",
            command=self.open_modify_popup,
            style="warning.TButton" 
        ).pack(side="left", padx=5)

        # Create a frame for subnet selection components
        subnet_frame = ttk.Frame(btn_frame)
        subnet_frame.pack(side="left", padx=5)

        # Suggest Next button
        ttk.Button(
            subnet_frame,
            text="Suggest Next",
            command=self.suggest_next_subnet,
            style="success.TButton"
        ).pack(side="left")

        # Subnet size dropdown
        self.subnet_size_var = tk.StringVar(value="/28")
        subnet_sizes = [f"/{i}" for i in range(24, 31)]
        subnet_combo = ttk.Combobox(
            subnet_frame,
            textvariable=self.subnet_size_var,
            values=subnet_sizes,
            state="readonly",
            width=4,
            font=config.BUTTON_FONT,
            style="Custom.TCombobox"
        )
        subnet_combo.pack(side="left", padx=(5, 5))

        # Configure Combobox style to match button styling
        self.style.configure(
            "Custom.TCombobox",
            font=config.BUTTON_FONT,
            padding=config.WIDGET_PADDING
        )

        # Load and sort initial data
        self.load_subnets()
        self.sort_treeview("CIDR")

    def on_double_click(self, event):
        """Handle double-click events on treeview entries"""
        try:
            # Get the item that was clicked
            item = self.tree.identify('item', event.x, event.y)
            if item:  # Ensure an item was actually clicked
                self.tree.selection_set(item)  # Select the clicked item
                self.open_modify_popup()  # Open the modify popup
        except Exception as e:
            self.update_flash_message(f"Error handling double-click: {str(e)}", "error")

    def suggest_next_subnet(self):
        """ Suggests the next available subnet of selected size immediately after the selected subnet """
        selected_item = self.tree.selection()
        if not selected_item:
            self.update_flash_message("Please select a subnet first.", "error")
            return

        selected_cidr = self.tree.item(selected_item)["values"][1]  # Get CIDR from selected row
        subnet_size = int(self.subnet_size_var.get().strip('/'))  # Remove '/' and convert to int

        try:
            # Ensure the selected CIDR is valid
            if not Utils.validate_cidr(selected_cidr):
                self.update_flash_message("Invalid CIDR format.", "error")
                return

            selected_network = ipaddress.ip_network(selected_cidr, strict=False)
            existing_subnets = {ipaddress.ip_network(subnet["cidr"], strict=False) 
                            for subnet in self.db.get_all_subnets()}

            # Define private IP address space limits
            private_ranges = [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            ]

            # Calculate the size of the new subnet block
            new_block_size = 2 ** (32 - subnet_size)
            
            # Start from the beginning of the selected network
            current_ip = int(selected_network.network_address)
            
            while True:
                # Convert the integer back to an IP address and create the network
                test_ip = ipaddress.ip_address(current_ip)
                test_network = ipaddress.ip_network(f"{test_ip}/{subnet_size}", strict=False)

                # If we've gone beyond the selected network's range and haven't found a spot,
                # move to the next network boundary after the selected network
                if current_ip >= int(selected_network.network_address) + selected_network.num_addresses:
                    # Find the next aligned boundary
                    current_ip = ((current_ip + new_block_size - 1) // new_block_size) * new_block_size
                    test_ip = ipaddress.ip_address(current_ip)
                    test_network = ipaddress.ip_network(f"{test_ip}/{subnet_size}", strict=False)

                # If the next network is outside of private address ranges, stop
                if not any(test_network.subnet_of(pr) for pr in private_ranges):
                    self.update_flash_message(
                        f"No available /{subnet_size} subnet within private IP ranges.", 
                        "error"
                    )
                    return

                # Check if this network overlaps with any existing network
                has_conflict = any(
                    test_network.overlaps(existing)
                    or existing.overlaps(test_network)
                    for existing in existing_subnets
                )

                # If no conflicts found, we've found our next available subnet
                if not has_conflict:
                    self.open_modify_popup(prefill_cidr=str(test_network), is_new_record=True)
                    return

                # Move to the next possible subnet position
                current_ip += new_block_size

        except ValueError as e:
            self.update_flash_message(f"Error computing the next /{subnet_size}: {str(e)}", "error")

    def sort_treeview(self, column):
        """Sorts the treeview data based on column"""
        data = [(self.tree.item(item, "values"), item) for item in self.tree.get_children("")]

        if column == "CIDR":
            key_func = lambda x: ipaddress.ip_network(x[0][1], strict=False)
        else:  # "Note"
            key_func = lambda x: x[0][2].lower()

        self.sort_reverse = not self.sort_reverse if self.sort_column == column else False
        self.sort_column = column

        data.sort(key=key_func, reverse=self.sort_reverse)

        for index, (_, item) in enumerate(data):
            self.tree.move(item, "", index)

    def update_flash_message(self, message, status="info"):
        """ Display flash messages """
        colors = {"info": "blue", "error": "red", "success": "green"}
        self.flash_message.config(text=message, foreground=colors.get(status, "black"))
        self.root.after(config.FLASH_TIME, lambda: self.flash_message.config(text=""))

    def on_search_input(self, event):
        """ Trigger search logic with delay """
        query = self.search_var.get()
        self.search_handler.trigger_search(query)

    def perform_search(self, query=""):
        for row in self.tree.get_children():
            self.tree.delete(row)

        results = self.db.search_subnets(query)
        for subnet in results:
            self.tree.insert("", "end", values=(subnet["id"], subnet["cidr"], subnet["note"]))

    def load_subnets(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        subnets = self.db.get_all_subnets()
        for subnet in subnets:
            self.tree.insert("", "end", values=(subnet["id"], subnet["cidr"], subnet["note"]))

    def open_modify_popup(self, prefill_cidr=None, is_new_record=False):
        """ Open a popup window for assigning/unassigning CIDR blocks """
        popup = tk.Toplevel(self.root)
        popup.title("Modify CIDR Assignment")
        popup.geometry("400x300")
        
        # Configure popup padding
        for child in popup.winfo_children():
            child.grid_configure(padx=config.WIDGET_PADDING, 
                            pady=config.WIDGET_PADDING)

        # CIDR Label and Entry
        ttk.Label(
            popup,
            text="CIDR",
            font=config.LABEL_FONT
        ).pack(pady=(config.WIDGET_PADDING, 2))
        
        cidr_entry = ttk.Entry(
            popup,
            font=config.ENTRY_FONT
        )
        cidr_entry.pack(padx=config.WIDGET_PADDING, 
                    pady=(2, config.WIDGET_PADDING))

        # Note Label and Entry
        ttk.Label(
            popup,
            text="Note",
            font=config.LABEL_FONT
        ).pack(pady=(config.WIDGET_PADDING, 2))
        
        note_entry = ttk.Entry(
            popup,
            font=config.ENTRY_FONT
        )
        note_entry.pack(padx=config.WIDGET_PADDING, 
                    pady=(2, config.WIDGET_PADDING))

        # Only get selected item data if this is NOT a new record
        selected_item = self.tree.selection() if not is_new_record else None
        subnet_values = self.tree.item(selected_item)["values"] if selected_item else None

        if subnet_values and not is_new_record:
            subnet_id, cidr, note = subnet_values
            cidr_entry.insert(0, cidr)
            note_entry.insert(0, note)
        else:
            subnet_id = None
            cidr_entry.insert(0, prefill_cidr if prefill_cidr else "")
            note_entry.insert(0, "")

        def save_changes(assign=True):
            """ Assign or unassign CIDR block """
            cidr = cidr_entry.get().strip()
            note = note_entry.get().strip()

            if not Utils.validate_cidr(cidr):
                messagebox.showerror("Error", "Invalid CIDR format.")
                return

            if assign:
                if not Utils.validate_note(note):
                    messagebox.showerror("Error", "Note cannot be empty.")
                    return

                existing_subnets = [subnet["cidr"] for subnet in self.db.get_all_subnets()]
                
                # For existing records, remove the current CIDR from conflict checking
                if subnet_id is not None:
                    current_cidr = self.tree.item(selected_item)["values"][1]
                    if cidr != current_cidr:  # Only check conflicts if CIDR is being changed
                        existing_subnets.remove(current_cidr)
                        conflict_msg = Utils.is_conflicting_subnet(cidr, existing_subnets)
                        if conflict_msg:
                            messagebox.showerror("Subnet Conflict", conflict_msg)
                            return
                        if cidr in existing_subnets:
                            messagebox.showerror("Error", "CIDR already assigned.")
                            return
                    # If CIDR is the same, just update the note
                    self.db.update_subnet(subnet_id, cidr, note)
                    self.update_flash_message("CIDR updated successfully", "success")
                else:  # New subnet
                    conflict_msg = Utils.is_conflicting_subnet(cidr, existing_subnets)
                    if conflict_msg:
                        messagebox.showerror("Subnet Conflict", conflict_msg)
                        return
                    if cidr in existing_subnets:
                        messagebox.showerror("Error", "CIDR already assigned.")
                        return
                    self.db.add_subnet(cidr, note)
                    self.update_flash_message("CIDR assigned successfully", "success")
            else:  # Unassign
                if subnet_id is not None:
                    self.db.delete_subnet(subnet_id)
                    self.update_flash_message("CIDR unassigned", "info")

            self.load_subnets()
            popup.destroy()

        # Button frame with updated styling
        btn_frame = ttk.Frame(popup)
        btn_frame.pack(pady=config.FRAME_PADDING)

        ttk.Button(
            btn_frame,
            text="Save",
            command=lambda: save_changes(True),
            style="TButton"
        ).pack(side="left", padx=5)
        
        # Only show Unassign button if this is not a new record
        if subnet_id is not None and not is_new_record:
            ttk.Button(
                btn_frame,
                text="Unassign",
                command=lambda: save_changes(False),
                style="danger.TButton" 
            ).pack(side="right", padx=5)


if __name__ == "__main__":
    root = tk.Tk()
    app = IPAMApp(root)
    root.mainloop()
