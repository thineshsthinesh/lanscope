# lanscope/engine/passive_monitor.py

import logging
import threading
from scapy.all import sniff, ARP, IP, IPv6
from queue import Queue

class PassiveMonitor(threading.Thread):
    """
    A passive network monitor that sniffs traffic to discover hosts.
    Runs in a separate thread and places discovered IPs into a shared queue.
    """
    def __init__(self, interface: str, event_queue: Queue):
        super().__init__(daemon=True)
        self.interface = interface
        self.event_queue = event_queue
        self.stop_sniffing = threading.Event()
        self.seen_ips = set()

    def _packet_handler(self, packet):
        """Callback function for each captured packet."""
        ip_to_add = None
        # We are interested in ARP packets and IP packets to find hosts
        if packet.haslayer(ARP) and packet.op in (1, 2): # ARP Request or Reply
            ip_to_add = packet.psrc
        elif packet.haslayer(IP):
            ip_to_add = packet[IP].src
        elif packet.haslayer(IPv6):
            # For this example, we focus on IPv4, but IPv6 discovery would go here
            ip_to_add = packet[IPv6].src

        if ip_to_add and ip_to_add not in self.seen_ips:
            # Add to a set to avoid flooding the queue with duplicate IPs
            self.seen_ips.add(ip_to_add)
            self.event_queue.put(ip_to_add)
            logging.info(f"Passively discovered host: {ip_to_add}")

    def run(self):
        """Starts the Scapy sniffer."""
        logging.info(f"Passive monitor started on interface {self.interface}")
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda p: self.stop_sniffing.is_set()
            )
        except Exception as e:
            logging.error(f"Error starting passive sniffer on '{self.interface}': {e}. "
                          "Please ensure the interface exists and you have root privileges.")

    def stop(self):
        """Signals the sniffer to stop."""
        logging.info("Stopping passive monitor...")
        self.stop_sniffing.set()