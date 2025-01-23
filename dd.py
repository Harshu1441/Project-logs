

from scapy.all import sniff, DNS, DNSQR, DNSRR
import psutil

def get_app_by_port(port):
    """
    Finds the application associated with a given port.
    """
    for conn in psutil.net_connections(kind='udp'):
        if conn.laddr.port == port:
            try:
                return psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return "Unknown"
    return "Unknown"

def process_dns_packet(packet):
    """
    Processes DNS packets to extract query/response details and app name.
    """
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        if dns_layer.qr == 0:  # Query
            query_name = dns_layer[DNSQR].qname.decode("utf-8")
            src_port = packet.sport
            app_name = get_app_by_port(src_port)
            print(f"DNS Query: {query_name}, Application: {app_name}")
        elif dns_layer.qr == 1:  # Response
            if DNSRR in dns_layer:
                response_name = dns_layer[DNSRR].rrname.decode("utf-8")
                response_data = dns_layer[DNSRR].rdata
                print(f"DNS Response: {response_name}, Resolved IP: {response_data}")

def main():
    """
    Captures DNS traffic on the system.
    """
    print("Starting DNS packet capture...")
    sniff(filter="udp port 53", prn=process_dns_packet, store=0)

if __name__ == "__main__":
    main()
