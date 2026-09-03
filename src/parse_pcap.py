from scapy.all import rdpcap, IP, TCP, UDP, ICMP, PcapReader
import pandas as pd
from pathlib import Path

def parsing_pcap(filepath: str) -> pd.DataFrame:
    """Parse un fichier PCAP et retourne un DataFrame structuré."""
    packets = rdpcap(filepath)
    datas = []

    for pkt in packets:
        if not IP in pkt:
            continue  # Ignore les paquets qui ne sont pas IP

        data = {
            "timestamp": float(pkt.time),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "length": len(pkt),
            "ttl": pkt[IP].ttl,
        }

        # classement selon le protocole
        if TCP in pkt:
            data["protocol"] = "TCP"
            data["src_port"] = pkt[TCP].sport
            data["dst_port"] = pkt[TCP].dport
            data["flags"] = str(pkt[TCP].flags)
        elif UDP in pkt:
            data["protocol"] = "UDP"
            data["src_port"] = pkt[UDP].sport
            data["dst_port"] = pkt[UDP].dport
            data["flags"] = None
        elif ICMP in pkt:
            data["protocol"] = "ICMP"
            data["src_port"] = None
            data["dst_port"] = None
            data["flags"] = None
        else:
            data["protocol"] = "Other"
            data["src_port"] = None
            data["dst_port"] = None
            data["flags"] = None

        datas.append(data)

    df = pd.DataFrame(datas)
    
    #conversion du timestamp
    df["datetime"] = pd.to_datetime(df["timestamp"], unit='s')

    return df

def parsing_pcap_streaming(filepath: str) -> pd.DataFrame:
    """Parse un fichier PCAP en streaming (pour les plus gros volumes) et retourne un DataFrame structuré."""
    datas = []

    with PcapReader(filepath) as pcap_reader:
        for pkt in pcap_reader:
            if not IP in pkt:
                continue  # Ignore les paquets qui ne sont pas IP

            data = {
                "timestamp": float(pkt.time),
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "length": len(pkt),
                "ttl": pkt[IP].ttl,
            }

            # classement selon le protocole
            if TCP in pkt:
                data["protocol"] = "TCP"
                data["src_port"] = pkt[TCP].sport
                data["dst_port"] = pkt[TCP].dport
                data["flags"] = str(pkt[TCP].flags)
            elif UDP in pkt:
                data["protocol"] = "UDP"
                data["src_port"] = pkt[UDP].sport
                data["dst_port"] = pkt[UDP].dport
                data["flags"] = None
            elif ICMP in pkt:
                data["protocol"] = "ICMP"
                data["src_port"] = None
                data["dst_port"] = None
                data["flags"] = None
            else:
                data["protocol"] = "Other"
                data["src_port"] = None
                data["dst_port"] = None
                data["flags"] = None

            datas.append(data)

    df = pd.DataFrame(datas)

    #conversion du timestamp
    df["datetime"] = pd.to_datetime(df["timestamp"], unit='s')

    return pd.DataFrame(datas)

if __name__ == "__main__":
    pcap_path = "data/capture.pcap"
    df = parsing_pcap(pcap_path)

    print(f"Nombre de paquets IP parsés : {len(df)} sur : {len(rdpcap(pcap_path))} paquets totaux")
    print(df.head())
    print(df["protocol"].value_counts())

    # export vers CSV
    output_path = Path("data") / "parsed_packets.csv"
    df.to_csv(output_path, index=False)
    print(f"DataFrame exporté vers : {output_path}")