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
