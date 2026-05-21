from scapy.all import IP, TCP, wrpcap
import random

def create_pcap():
    pkts = []
    print("Génération du fichier test_attack.pcap...")
    
    # 5 paquets normaux (trafic web)
    for _ in range(5):
        pkts.append(IP(src="192.168.1.50", dst="104.244.42.1")/TCP(dport=443, flags="A"))
    
    # 30 paquets d'attaque (scan de ports agressif)
    for _ in range(30):
        pkts.append(IP(src="185.60.216.35", dst="192.168.1.1")/TCP(dport=random.randint(20, 1024), flags="S"))
        
    wrpcap("test_attack.pcap", pkts)
    print("Fichier test_attack.pcap généré avec succès (35 paquets) !")

if __name__ == "__main__":
    create_pcap()
