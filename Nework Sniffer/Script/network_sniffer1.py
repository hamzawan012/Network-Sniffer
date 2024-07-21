from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    with open("packet_log.txt", "a") as f:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            f.write(f"IP Packet: {ip_src} -> {ip_dst} (Protocol: {protocol})\n")
            if TCP in packet:
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                f.write(f"TCP Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}\n")
            elif UDP in packet:
                udp_sport = packet[UDP].sport
                udp_dport = packet[UDP].dport
                f.write(f"UDP Packet: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}\n")
            elif ICMP in packet:
                icmp_type = packet[ICMP].type
                f.write(f"ICMP Packet: {ip_src} -> {ip_dst} (Type: {icmp_type})\n")
            if Raw in packet:
                raw_data = packet[Raw].load
                f.write(f"Raw Data: {raw_data}\n")

if __name__ == "__main__":
    print("Starting the packet sniffer...")
    # Filter for only TCP packets and start the sniffer
    sniff(prn=packet_callback, store=0, filter="tcp")
