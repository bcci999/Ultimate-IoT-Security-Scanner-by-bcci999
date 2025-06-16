# Ultimate IoT Security Scanner by bcci999

A comprehensive tool for scanning and auditing IoT devices for open ports, weak credentials, vulnerabilities (including Mirai, Ripple20, UPnP), insecure configurations, and much more!

## Features

- **Port Scanning**: Scans a wide range of TCP and UDP ports, including common IoT and industrial ports.
- **Device Classification**: Detects device types (IP cameras, routers, printers, VOIP, etc.) by banners and ports.
- **Vulnerability Scanning**: Checks for known exploits and vulnerabilities, including Mirai botnet, Ripple20, Hikvision, D-Link, and more.
- **Credential Checks**: Attempts login with default and weak credentials for HTTP, Telnet, FTP, etc.
- **Protocol Audits**: Tests for insecure or exposed protocols (MQTT, CoAP, Modbus, BACnet, UPnP, etc.).
- **Deep Inspection**: Inspects for exposed firmware versions, cloud connections, wireless configs, industrial backdoors, and other misconfigurations.
- **Nmap Integration**: Uses Nmap (if installed) for service and vulnerability scanning with script support.
- **Proxy Support**: Supports scanning via SOCKS5/HTTP proxy (single or via proxy list).
- **Concurrent Scanning**: Multi-threaded with user-defined worker count for fast scanning.
- **Custom Command Trigger**: Optionally runs a custom shell command if vulnerabilities are found.
- **Flexible Output**: Saves reports per device and a global JSON report.

## Usage

```bash
go run iot_scanner.go -ipfile=devices.txt [options]
