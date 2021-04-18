import pyshark
import time

#use twilio
"""
import os
from twilio.rest import Client


# Your Account Sid and Auth Token from twilio.com/console
# and set the environment variables. See http://twil.io/secure
def sendMessage():
    account_sid = os.environ['TWILIO_ACCOUNT_SID']
    auth_token = os.environ['TWILIO_AUTH_TOKEN']
    client = Client(account_sid, auth_token)

    message = client.messages \
                    .create(
                         body="Capture packets has started",
                         from_='+254..',
                         to='+254..'
                     )

    print(message.sid)
"""




# define interface
networkInterface = "wlo1"

# define capture object
capture = pyshark.LiveCapture(interface=networkInterface)


def capturePackets():
    print("listening on %s" % networkInterface)

    for packet in capture.sniff_continuously():
        # adjusted output
        #try:
            # get timestamp
        localtime = time.asctime(time.localtime(time.time()))

        # get packet content
        protocol = packet.transport_layer   # protocol type
        src_addr = packet.ip.src            # source address
        src_port = packet[protocol].srcport   # source port
        dst_addr = packet.ip.dst            # destination address
        dst_port = packet[protocol].dstport   # destination port



        list1 = []
        list1.append(protocol)
        print(list1)




        # output packet info
        print ("%s IP %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol))
        count = 2
        while count<2:
            sendMessage()

        #except AttributeError as e:
            # ignore packets other than TCP, UDP and IPv4
        #    pass
        #print (" ")
    print(list1)
    len_list = len(list1)
    print(len(list1))
    tcp_count = list1.count("TCP")
    udp_count = list1.count("UDP")
    #print(list1.count("TCP")
    #perc_tcp = (tcp_count/len_list) * 100
    perc_tcp = (tcp_count/len_list) * 100
    perc_udp = (udp_count/len_list) * 100
    print("TCP traffic: ", perc_tcp, "%")
    print("UDP traffic: ", perc_udp, "%")


capturePackets()
