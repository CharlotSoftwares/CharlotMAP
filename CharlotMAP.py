import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QLabel
)
from scapy.all import ARP, Ether, srp
import socket
import threading

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

        # Run scan in separate thread to not freeze GUI
        threading.Thread(target=self._scan).start()

    def _scan(self):
        # Common local network subnet for Wi-Fi, adjust if needed
        ip_range = "192.168.1.0/24"

        # Create ARP request packet
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=0)[0]

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
