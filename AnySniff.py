import subprocess
import re
import time
from datetime import datetime
from colorama import init, Fore, Style
import pyfiglet
import os
import threading
import requests

init(autoreset=True)

# info about ip from ip-api.com
def get_ip_info(ip_address):
    url = f"http://ip-api.com/json/{ip_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return data
            else:
                return None
        else:
            return None
    except Exception as e:
        log_message(Style.BRIGHT + Fore.RED + f"Error fetching IP info: {e}")
        return None

# log name
def generate_log_filename():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"ip_{timestamp}.log"

LOG_FILE = generate_log_filename()

# logging messages
def log_message(message):
    timestamp = datetime.now().strftime("[%H:%M:%S]")
    formatted_message = f"{timestamp} {message}"
    print(formatted_message)
    with open(LOG_FILE, "a") as log_file:
        log_file.write(formatted_message + "\n")

# ip sniff
def parse_netstat_output_targeted(target_process_name):
    try:
        result = subprocess.run(['netstat', '-ano'], stdout=subprocess.PIPE, text=True)
        output = result.stdout
        netstat_pattern = re.compile(r'\s+TCP\s+([\d.]+):(\d+)\s+([\d.]+):(\d+)\s+ESTABLISHED\s+(\d+)')
        matches = netstat_pattern.findall(output)

        for match in matches:
            local_ip, local_port, remote_ip, remote_port, pid = match

            if remote_ip == "0.0.0.0" or remote_port in {"0", "80", "443"}:
                continue

            try:
                process_name = subprocess.run(
                    ['tasklist', '/FI', f'PID eq {pid}'],
                    stdout=subprocess.PIPE, text=True
                ).stdout

                if target_process_name.lower() in process_name.lower():
                    print(Style.BRIGHT + Fore.YELLOW + "-" * 40)
                    log_message(Style.BRIGHT + Fore.GREEN + f"Process: {target_process_name}")
                  # log_message(Style.BRIGHT + Fore.GREEN + f"Local IP: {local_ip}, Port: {local_port}")

                    # Get IP info
                    ip_info = get_ip_info(remote_ip)
                    if ip_info:
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Remote IP: {remote_ip}, Port: {remote_port}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Country: {ip_info.get('country', 'N/A')} ({ip_info.get('countryCode', 'N/A')})")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Region: {ip_info.get('regionName', 'N/A')} ({ip_info.get('region', 'N/A')})")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"City: {ip_info.get('city', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"ZIP: {ip_info.get('zip', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Coordinates: Lat {ip_info.get('lat', 'N/A')}, Lon {ip_info.get('lon', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Timezone: {ip_info.get('timezone', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"ISP: {ip_info.get('isp', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Organization: {ip_info.get('org', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"AS: {ip_info.get('as', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Query: {ip_info.get('query', 'N/A')}")
                    else:
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Remote IP: {remote_ip}, Port: {remote_port} (No additional info available)")

                    log_message(Style.BRIGHT + Fore.GREEN + f"PID: {pid}")
                    print(Style.BRIGHT + Fore.YELLOW + "-" * 40)

            except Exception as ex:
                log_message(Style.BRIGHT + Fore.RED + f"Error processing PID {pid}: {ex}")

    except Exception as e:
        log_message(Style.BRIGHT + Fore.RED + f"Error executing netstat: {e}")

# monitor func
def monitor_targeted_connections(target_process_name, stop_event):
    while not stop_event.is_set():
        log_message(Style.BRIGHT + Fore.GREEN + "Monitoring targeted TCP connections, wait...")
        parse_netstat_output_targeted(target_process_name)
        time.sleep(1)

# logo
def display_logo():
    logo = pyfiglet.figlet_format("Any Sniff", font="defleppard")
    print(Style.BRIGHT + Fore.CYAN + logo)
    print(Style.BRIGHT + Fore.MAGENTA + "By MKultra69")
    print(Style.BRIGHT + Fore.YELLOW + "-" * 40)

# menu
def main_menu():
    while True:
        display_logo()
        print(Style.BRIGHT + Fore.GREEN + "1. Start Sniff")
        print(Style.BRIGHT + Fore.BLUE + "2. Info")
        print(Style.BRIGHT + Fore.RED + "3. Exit")
        print(Style.BRIGHT + Fore.YELLOW + "-" * 40)

        choice = input(Style.BRIGHT + Fore.WHITE + "Select an option: ")

        if choice == "1":
            log_message(Style.BRIGHT + Fore.GREEN + "Starting sniffing...")
            monitor_menu()
        elif choice == "2":
            display_info()
        elif choice == "3":
            log_message(Style.BRIGHT + Fore.GREEN + "Exiting...")
            break
        else:
            log_message(Style.BRIGHT + Fore.RED + "Invalid choice. Try again.")

# exit to menu out monitor
def monitor_menu():
    stop_event = threading.Event()
    target_process_name = "AnyDesk"
    sniff_thread = threading.Thread(target=monitor_targeted_connections, args=(target_process_name, stop_event))
    sniff_thread.start()

    try:
        while True:
            choice = input(Style.BRIGHT + Fore.WHITE + "      Press 'm' to menu: ").strip().lower()
            if choice =='m':
               stop_event.set()
               sniff_thread.join()
               break
    except KeyboardInterrupt:
        stop_event.set()
        sniff_thread.join()
        log_message(Style.BRIGHT + Fore.GREEN + "Returning to the main menu...")

# info menu
def display_info():
    while True:
        print(Style.BRIGHT + Fore.YELLOW + "-" * 40)
        print(Style.BRIGHT + Fore.CYAN + "This tool monitors traffic using " + Style.BRIGHT + Fore.RED + "CVE-2024-52940.")
        print(Style.BRIGHT + Fore.CYAN + "It only works with AnyDesk up to version 8.1.0 on Windows when the 'Allow direct connections' option is enabled.")
        print(Style.BRIGHT + Fore.CYAN + "Created by MKultra69")
        print(Style.BRIGHT + Fore.YELLOW + "-" * 40)
        input(Style.BRIGHT + Fore.WHITE + "Press 'Enter' to return to the main menu.")
        break


if __name__ == "__main__":
    log_message(f"Program started. Logs saved to {LOG_FILE}")
    main_menu()
