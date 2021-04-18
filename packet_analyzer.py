import pyshark

cap = pyshark.LiveCapture(interface='wlo1', bpf_filter='udp port 53, 443, 21, 25')
cap.sniff(packet_count = 15)

def dnsInfo(pkt):
    if pkt.dns.qry_name:
        print("DNS Request from {}: {}".format(pkt.ip.src, pkt.dns.qry_name))
    elif pkt.dns.resp_name:
        print("DNS Response from {}: {}".format(pkt.ip.src, pkt.dns.resp_name))


cap.apply_on_packets(dnsInfo, timeout=100)
