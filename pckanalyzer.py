import pyshark

capture = pyshark.LiveCapture(interface='wlo1')
capture.sniff(packet_count=5)
print(capture)
for packet in capture:
    print(packet)
