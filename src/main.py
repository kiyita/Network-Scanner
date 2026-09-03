from scapy.all import rdpcap
pkts = rdpcap("data/capture.pcap")
print(f"Nombre de paquets : {len(pkts)}")
print(pkts[0].summary())