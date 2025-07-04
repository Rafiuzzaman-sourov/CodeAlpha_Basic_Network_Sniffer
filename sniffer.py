import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
from datetime import datetime

captured_packets = []
stop_sniffing = False

def process_packet(packet):
    captured_packets.append(packet)

    if IP in packet:
        print(f"[IP] {packet[IP].src} -> {packet[IP].dst} | Proto: {packet[IP].proto}")
    if TCP in packet:
        print(f"[TCP] Port: {packet[TCP].sport} -> {packet[TCP].dport}")
    elif UDP in packet:
        print(f"[UDP] Port: {packet[UDP].sport} -> {packet[UDP].dport}")
    elif ICMP in packet:
        print("[ICMP] Packet")
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors='ignore')
            print(f"[Raw Payload]: {payload[:60]}")
        except:
            pass

def sniff_packets():
    sniff(filter="ip", prn=process_packet, store=False, stop_filter=lambda x: stop_sniffing)

def command_listener():
    global stop_sniffing
    while True:
        cmd = input("\n🔹 Type 'save' to save PCAP or 'exit' to stop and save: ").strip().lower()
        if cmd == "save":
            filename = input(" Enter filename (without .pcap): ").strip()
            if not filename:
                filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            filename += ".pcap"
            wrpcap(filename, captured_packets)
            print(f" Saved {len(captured_packets)} packets to {filename}")
        elif cmd == "exit":
            stop_sniffing = True
            break

if __name__ == "__main__":
    print(" Starting Sniffer... type 'save' or 'exit' anytime below.")
    sniffer_thread = threading.Thread(target=sniff_packets)
    sniffer_thread.start()
    command_listener()
    sniffer_thread.join()
    print(" Sniffing stopped.")
