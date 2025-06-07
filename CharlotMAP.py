import sys
import socket
import threading
from ipaddress import IPv4Interface

import netifaces
from scapy.all import ARP, Ether, srp
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QLabel
)

def get_local_network_cidr():
    for iface in netifaces.interfaces():
        if iface == "lo":
            continue
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ipv4_info = addrs[netifaces.AF_INET][0]
            ip = ipv4_info['addr']
            netmask = ipv4_info['netmask']
            interface = IPv4Interface(f"{ip}/{netmask}")
            network = interface.network
            return str(network)
    return None

class CharlotScanWiFi(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CharlotScan Wi-Fi")
        self.setGeometry(300, 300, 600, 400)

        layout = QVBoxLayout()

        self.info_label = QLabel("Click 'Scan Wi-Fi Devices' to start scanning.")
        layout.addWidget(self.info_label)

        self.scan_button = QPushButton("Scan Wi-Fi Devices")
        self.scan_button.clicked.connect(self.scan_network)
        layout.addWidget(self.scan_button)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Hostname"])
        layout.addWidget(self.table)

        self.setLayout(layout)

    def scan_network(self):
        self.info_label.setText("Scanning... Please wait.")
        self.scan_button.setEnabled(False)
        self.table.setRowCount(0)

        threading.Thread(target=self._scan).start()

    def _scan(self):
        ip_range = get_local_network_cidr()
        if not ip_range:
            self.info_label.setText("Error: Could not determine network range.")
            self.scan_button.setEnabled(True)
            return

        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        try:
            result = srp(packet, timeout=3, verbose=0)[0]
        except PermissionError:
            self.info_label.setText("Error: Run this program with sudo/root for scanning.")
            self.scan_button.setEnabled(True)
            return

        devices = []
        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = "Unknown"
            devices.append((ip, mac, hostname))

        self.update_table(devices)

    def update_table(self, devices):
        self.table.setRowCount(len(devices))
        for row, (ip, mac, hostname) in enumerate(devices):
            self.table.setItem(row, 0, QTableWidgetItem(ip))
            self.table.setItem(row, 1, QTableWidgetItem(mac))
            self.table.setItem(row, 2, QTableWidgetItem(hostname))

        self.info_label.setText(f"Scan complete: {len(devices)} device(s) found.")
        self.scan_button.setEnabled(True)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CharlotScanWiFi()
    window.show()
    sys.exit(app.exec_())
