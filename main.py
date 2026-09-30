import sys

from port_checker import scan_ports, display_results

from login_monitor import (

    record_attempt,

    show_recent_attempts,

    security_summary,

    check_for_brute_force,

    CSV_FILE,

)

import os

 

 

def clear_screen():

    """Clear the terminal screen."""

    os.system("cls" if os.name == "nt" else "clear")

 

 

def print_menu():

    print("")

    print("======================================================")

    print(" BASIC NETWORK AND LOGIN SECURITY MONITOR")

    print("======================================================")

    print(" 1. Scan ports on a host")

    print(" 2. Record a login attempt")

    print(" 3. View recent login attempts")

    print(" 4. Security summary (suspicious activity)")

    print(" 5. Clear login log")

    print(" 6. Exit")

    print("======================================================")

 

 

def option_port_scan():

    target = input("Enter IP or hostname to scan: ").strip()

    if not target:

        print("No host entered.")

        return

    try:

        results = scan_ports(target)

        display_results(target, results)

    except ValueError as e:

        print("ERROR: " + str(e))

 

 

def option_record_login():

    username = input("Username: ").strip()

    ip_address = input("IP address (e.g., 192.168.1.15): ").strip()

    if not username or not ip_address:

        print("Username and IP are required.")

        return

 

    answer = input("Was the login successful? (y/n): ").strip().lower()

    success = (answer == "y")

 

    record_attempt(username, ip_address, success)

 

    # Immediately check if this IP just triggered the alert

    if not success:

        check_for_brute_force(ip_address)

 

 

def option_view_recent():

    show_recent_attempts()

 

 

def option_security_summary():

    security_summary()

 

 

def option_clear_log():

    confirm = input("Are you sure you want to delete the login log? (y/n): ").strip().lower()

    if confirm == "y":

        if os.path.exists(CSV_FILE):

            os.remove(CSV_FILE)

            print("Login log cleared.")

        else:

            print("No log file to clear.")

    else:

        print("Cancelled.")

 

 

def main():

    while True:

        print_menu()

        choice = input("Choose an option [1-6]: ").strip()

 

        if choice == "1":

            option_port_scan()

        elif choice == "2":

            option_record_login()

        elif choice == "3":

            option_view_recent()

        elif choice == "4":

            option_security_summary()

        elif choice == "5":

            option_clear_log()

        elif choice == "6":

            print("Goodbye.")

            sys.exit(0)

        else:

            print("Invalid choice. Please enter a number from 1 to 6.")

 

        input("\nPress Enter to continue...")

 

 

if __name__ == "__main__":

    main()