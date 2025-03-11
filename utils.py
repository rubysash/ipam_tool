import re
import ipaddress


class Utils:
    """ Contains helper functions for validation """

    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        """
        Validate if the given string is a valid CIDR notation.

        Args:
            cidr (str): CIDR notation to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        try:
            ipaddress.IPv4Network(cidr, strict=False)
            return True
        except (ValueError, ipaddress.NetmaskValueError):
            return False

    @staticmethod
    def validate_note(note: str) -> bool:
        """
        Ensure the note follows the expected format (alphanumeric and spaces).

        Args:
            note (str): The note to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        return bool(re.fullmatch(r"[A-Za-z0-9 ]{1,100}", note))

    @staticmethod
    def is_conflicting_subnet(new_cidr, existing_subnets):
        """
        Check if the new subnet is a smaller subset of an existing larger subnet.

        Args:
            new_cidr (str): The CIDR to check.
            existing_subnets (list): List of existing CIDRs.

        Returns:
            str or None: Returns an error message if a conflict is found, else None.
        """
        new_network = ipaddress.ip_network(new_cidr, strict=True)

        for existing_cidr in existing_subnets:
            existing_network = ipaddress.ip_network(existing_cidr, strict=True)
            if existing_network.supernet_of(new_network):
                return f"Error: Cannot assign {new_cidr} because {existing_cidr} already exists and covers this range."

        return None

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format."""
        return bool(re.fullmatch(r"[^@]+@[^@]+\.[a-zA-Z]{2,}", email))

    @staticmethod
    def export_aws_secrets(db_manager, parent_window=None):
        """
        Export all secrets in AWS Secrets Manager format to a file.
        
        Args:
            db_manager: DatabaseManager instance with the database connection
            parent_window: Parent window for file dialog
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            import json
            import tkinter.filedialog as filedialog
            from tkinter import messagebox
            from datetime import datetime
            
            # Get secrets in AWS format
            secrets = db_manager.export_secrets_aws_format()
            
            # Debug information
            num_secrets = len(secrets)
            print(f"Found {num_secrets} secrets to export")
            
            if not secrets:
                if parent_window:
                    messagebox.showinfo("Export Results", "No secrets found to export.")
                return False
            
            # Generate default filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"ipam_secrets_{timestamp}.json"
            
            # Ask user where to save the file
            file_path = filedialog.asksaveasfilename(
                parent=parent_window,
                defaultextension=".json",
                initialfile=default_filename,
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
            )
            
            if not file_path:  # User cancelled
                return False
            
            # Write secrets to file in JSON format
            with open(file_path, 'w') as f:
                json.dump(secrets, f, indent=2)
            
            if parent_window:
                messagebox.showinfo("Export Success", f"Successfully exported {num_secrets} secrets to {file_path}")
            
            return True
        except Exception as e:
            if parent_window:
                messagebox.showerror("Export Error", f"Error exporting secrets: {str(e)}")
            print(f"Error exporting secrets: {e}")
            return False