# Basic Network and Login Security Monitor

 

A beginner-friendly Python cybersecurity tool that detects two common

security concerns: **repeated failed login attempts** and **open network ports**.

 

Built as a hands-on learning project to demonstrate brute-force detection,

network reconnaissance, and simple security monitoring concepts.

 

---

 

## Features

 

### 1. Login Attempt Monitor

- Records every login attempt (username, IP, timestamp, success/failure)

- Stores attempts in a CSV file for persistence

- Detects brute-force attacks:

  - Same IP with many failures (classic brute-force)

  - Same IP trying many usernames (username spraying)

- Assigns a **risk score (0–10)** to suspicious IPs

- Fires an alert when the threshold is exceeded

 

### 2. Port Checker

- Checks common ports on any IP or hostname:

  - 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 443 (HTTPS)

- Reports each port as OPEN or CLOSED

- Configurable timeout to avoid hanging on unreachable hosts

 

### 3. Interactive Menu

- Single entry point (`main.py`) to access all features

- Clear, numbered options

- Handles invalid input gracefully

 

---

 

## Requirements

 

- Python 3.7 or higher

- No external packages — uses only the standard library

  (`socket`, `csv`, `os`, `datetime`, `sys`)

 

---

 

## Installation

 

1. Clone or download this folder

2. Open a terminal (Git Bash, PowerShell, or Terminal on Mac/Linux)

3. Navigate into the project folder:

 

   ```bash

   cd security_monitor
   python3 login_monitor.py
   python3 main.py
   python3 port_checker.py
   ```
   
