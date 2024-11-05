from scapy.all import IP, ICMP, send

receiver_ip = "172.23.0.3"
ttl_value = 1

ip_packet = IP(dst=receiver_ip, ttl=ttl_value)

icmp_packet = ICMP()

packet = ip_packet / icmp_packet

send(packet)
