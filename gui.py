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
        self.root.geometry("1024x800")
        
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
        """ Create search bar, messages, treeview, and modify button with updated columns """
        # Search Label and Entry
        search_label = ttk.Label(self.frame0, text="Search:", font=config.LABEL_FONT)
        search_label.pack(side="left", padx=config.WIDGET_PADDING)

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self.frame0, textvariable=self.search_var, font=config.ENTRY_FONT)
        self.search_entry.pack(fill="x", expand=True, padx=config.WIDGET_PADDING, pady=config.WIDGET_PADDING)
        self.search_entry.bind("<KeyRelease>", self.on_search_input)

        # Flash Message
        self.flash_message = ttk.Label(self.frame1, text="", foreground="red", font=config.MESSAGE_FONT, wraplength=550)
        self.flash_message.pack(pady=config.WIDGET_PADDING)

        # CIDR Blocks Label
        header_label = ttk.Label(self.frame2, text="Assigned CIDR Blocks", font=config.HEADING_FONT)
        header_label.pack(anchor="w", padx=config.WIDGET_PADDING, pady=config.WIDGET_PADDING)

        # Treeview Setup
        tree_frame = ttk.Frame(self.frame2)
        tree_frame.pack(fill="both", expand=True, pady=config.WIDGET_PADDING)

        self.tree = ttk.Treeview(tree_frame, columns=(
            "ID", "CIDR", "Note", "Cust", "Cust Email", "Dev IP", "CGW IP"
        ), show="headings", style="Treeview")

        # Configure column headers
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(c))
            self.tree.column(col, anchor="center", minwidth=100 if col != "ID" else 0)

        self.tree.column("ID", width=0, stretch=False)  # Hide ID column

        # Add double-click binding
        self.tree.bind("<Double-1>", self.on_double_click)

        # Scrollbar
        y_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=y_scroll.set)
        y_scroll.pack(side="right", fill="y")

        self.tree.pack(fill="both", expand=True)

        # Button and Subnet Size Selection Frame
        btn_frame = ttk.Frame(self.frame3)
        btn_frame.pack(pady=config.FRAME_PADDING)

        ttk.Button(btn_frame, text="Add", command=lambda: self.open_modify_popup(None, True), style="success.TButton").pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Modify", command=self.open_modify_popup, style="warning.TButton").pack(side="left", padx=5)

        subnet_frame = ttk.Frame(btn_frame)
        subnet_frame.pack(side="left", padx=5)

        ttk.Button(subnet_frame, text="Suggest Next", command=self.suggest_next_subnet, style="success.TButton").pack(side="left")

        self.subnet_size_var = tk.StringVar(value="/28")
        subnet_sizes = [f"/{i}" for i in range(24, 31)]
        subnet_combo = ttk.Combobox(subnet_frame, textvariable=self.subnet_size_var, values=subnet_sizes, state="readonly", width=4, font=config.BUTTON_FONT)
        subnet_combo.pack(side="left", padx=5)

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
        """ Load subnets into the Treeview, masking passwords. """
        for row in self.tree.get_children():
            self.tree.delete(row)

        subnets = self.db.get_all_subnets()
        for subnet in subnets:
            masked_pass = "*****" if subnet["dev_pass"] else ""
            self.tree.insert("", "end", values=(
                subnet["id"], subnet["cidr"], subnet["note"], subnet["cust"], subnet["cust_email"],
                subnet["dev_type"], subnet["dev_ip"], subnet["dev_user"], masked_pass, 
                subnet["cgw_ip"], subnet["vpn1_psk"], subnet["vpn2_psk"]
            ))

    def open_modify_popup(self, prefill_cidr=None, is_new_record=False):
        """ Open a popup to modify subnet details, displaying in two equal columns. """
        popup = tk.Toplevel(self.root)
        popup.title("Modify Subnet")
        popup.geometry("600x400")

        # Define fields for input (Dev Type, Dev User, Dev Pass, VPN1 PSK, VPN2 PSK will not be in the main tree)
        fields = [
            ("CIDR", "cidr"), ("Note", "note"), ("Cust", "cust"), ("Cust Email", "cust_email"),
            ("Dev IP", "dev_ip"), ("CGW IP", "cgw_ip"), ("Dev Type", "dev_type"),
            ("Dev User", "dev_user"), ("Dev Pass", "dev_pass"), ("VPN1 PSK", "vpn1_psk"), ("VPN2 PSK", "vpn2_psk")
        ]

        entries = {}

        # Create two-column layout
        form_frame = ttk.Frame(popup)
        form_frame.pack(padx=20, pady=20, fill="both", expand=True)

        for i, (label_text, key) in enumerate(fields):
            row, col = divmod(i, 2)  # Arrange in two columns

            ttk.Label(form_frame, text=label_text, font=config.LABEL_FONT).grid(row=row, column=col * 2, padx=10, pady=5, sticky="w")

            show_value = "*" if key == "dev_pass" else ""
            entries[key] = ttk.Entry(form_frame, font=config.ENTRY_FONT, show=show_value)
            entries[key].grid(row=row, column=(col * 2) + 1, padx=10, pady=5, sticky="ew")

        form_frame.columnconfigure(1, weight=1)
        form_frame.columnconfigure(3, weight=1)

        # Get selected item data if modifying
        selected_item = self.tree.selection() if not is_new_record else None
        subnet_values = self.tree.item(selected_item)["values"] if selected_item else None

        if subnet_values:
            stored_values = {
                "cidr": subnet_values[1], "note": subnet_values[2], "cust": subnet_values[3],
                "cust_email": subnet_values[4], "dev_ip": subnet_values[5], "cgw_ip": subnet_values[6]
            }
            db_entry = self.db.get_all_subnets()
            full_data = next((s for s in db_entry if s["cidr"] == stored_values["cidr"]), {})
            stored_values.update(full_data)

            for key, entry in entries.items():
                entry.insert(0, stored_values.get(key, ""))

        # Save changes function
        def save_changes():
            data = {key: entry.get().strip() for key, entry in entries.items()}

            if not Utils.validate_cidr(data["cidr"]):
                messagebox.showerror("Error", "Invalid CIDR format.")
                return
            if not Utils.validate_email(data["cust_email"]):
                messagebox.showerror("Error", "Invalid email format.")
                return

            if subnet_values:
                self.db.update_subnet(
                    subnet_values[0], data["cidr"], data["note"], data["cust"], data["cust_email"],
                    data["dev_type"], data["dev_ip"], data["dev_user"], data["dev_pass"],
                    data["cgw_ip"], data["vpn1_psk"], data["vpn2_psk"]
                )
                self.update_flash_message("Subnet updated successfully", "success")
            else:
                self.db.add_subnet(
                    data["cidr"], data["note"], data["cust"], data["cust_email"], data["dev_type"],
                    data["dev_ip"], data["dev_user"], data["dev_pass"], data["cgw_ip"],
                    data["vpn1_psk"], data["vpn2_psk"]
                )
                self.update_flash_message("Subnet added successfully", "success")

            self.load_subnets()
            popup.destroy()

        # Save button
        ttk.Button(popup, text="Save", command=save_changes, style="TButton").pack(pady=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = IPAMApp(root)
    root.mainloop()
