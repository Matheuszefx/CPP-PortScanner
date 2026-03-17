# CPP-PortScanner
#  Port Scanner

A simple TCP port scanner written in C++ using BSD sockets.

## Features

- Scans a range of ports on a target IP
- Identifies common services (FTP, SSH, HTTP, HTTPS, etc.)
- Configurable scan interval between ports

## How to Compile

```bash
g++ newc.cpp -o scanner
```

## How to Use

```bash
./scanner
```

You will be prompted to enter:
- Target IP address
- Time interval between scans (in seconds)
- Number of ports to scan

## Example

```
----------MUNHOZ SCANNER----------
Enter target IP:
192.168.1.1
Enter scan interval (seconds):
1
Enter number of ports:
100
Open port: 80 HTTP
Open port: 443 HTTPS
```

## Supported Services

| Port | Service |
|------|---------|
| 21   | FTP     |
| 22   | SSH     |
| 23   | Telnet  |
| 25   | SMTP    |
| 53   | DNS     |
| 80   | HTTP    |
| 110  | POP3    |
| 143  | IMAP    |
| 443  | HTTPS   |
| 3389 | RDP     |

## ⚠️ Ethical Use

This tool is intended for **educational purposes only**.  
Only use it on networks and systems you own or have explicit permission to scan.  
Unauthorized port scanning may be illegal in your country.

## Author

[Matheuszefx](https://github.com/Matheuszefx)
