import socket

 

COMMON_PORTS = {

    21: "FTP",

    22: "SSH",

    23: "Telnet",

    25: "SMTP",

    53: "DNS",

    80: "HTTP",

    443: "HTTPS",

}

 

 

def check_port(host, port, timeout=1):

    try:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex((host, port))

            return result == 0

    except socket.gaierror:

        raise ValueError("Could not resolve hostname: " + host)

    except socket.error:

        return False

 

 

def scan_ports(host, port_list=None):

    if port_list is None:

        port_list = COMMON_PORTS

 

    results = []

    for port, service in port_list.items():

        is_open = check_port(host, port)

        results.append((port, service, is_open))

    return results

 

 

def display_results(host, results):

    print("")

    print("Port scan results for: " + host)

    print("-" * 40)

    for port, service, is_open in results:

        status = "OPEN" if is_open else "CLOSED"

        print(str(port).ljust(6) + service.ljust(10) + "- " + status)

    print("-" * 40)

 

 

if __name__ == "__main__":

    target = input("Enter IP or hostname to scan: ").strip()

    try:

        results = scan_ports(target)

        display_results(target, results)

    except ValueError as e:

        print("ERROR: " + str(e))