from scapy.all import sniff

def process_packet(packet):
    if packet.haslayer('ICMP'):
        packet.show() 

#Wait for the incoming package
sniff(filter="icmp", prn=process_packet, store=0)
