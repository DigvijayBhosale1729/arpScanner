# Created by FoxSinOfGreed1729
# Many thanks to Zaid Sabih and udemy.com

import scapy.all as scapy
import optparse


# Scans a specific host or an entire network, but not recommended for entire network
# uses unicast messages
# to list the people and devices on your local network
def arpScanUnicast(ip):
    scapy.arping(ip)


# Scans entire network using Broadcast messages
def arpScanBroadcast(ip):
    # scapy.ls(scapy.ARP()) will print out all parameters that can be set for the arp query
    # we're interested in the field IPField
    arp_req = scapy.ARP(pdst=ip)
    # print(arp_req.summary())
    # now that we've created the ARP request, we need to broadcast it
    # to broadcast, we need to create an ethernet frame with destination MAC as broadcast MAC
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # print(broadcast.summary())
    # We still haven't created the ethernet frame.
    # the ethernet frame has 2 parts, the data and the MAC
    # we've created both parts and now we'll combine them and create an actual packet
    arp_broadcast = broadcast / arp_req
    # arp_broadcast.show()
    # the above command shows the details of each of the packets

    # we still haven't sent a packet, so we'll do that now
    answered, unanswered = scapy.srp(arp_broadcast, timeout=2, verbose=False)
    # if you want the program to show details, put in (arp_broadcast, timeout=1, verbose=True)
    # this will send a request and returns a couple of 2 lists
    # the timeout is 1, it means, exit if you don't get a response within 1 sec
    # We have results in answered list, but we need the important stuff in a variable
    # to extract this info, we print out using print(answered)
    # that gives the actual list, and we see there are so many parameters
    hwsrc_list = []
    psrc_list = []
    for element in answered:
        # element[1] is the part that gives the response of the clients
        # and what we want is the psrc (IP Source) and hwsrc (HardWare Src)
        # so we do element[1].psrc and element[1].hwsrc
        # this gives the psrc and hsrc of client, but client here is the device that replies to out arp req
        hwsrc_list.append(element[1].hwsrc)
        psrc_list.append(element[1].psrc)
    client_list = [hwsrc_list, psrc_list]
    return client_list


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--ip', dest='ip_addr', help='The local IP address or IP Address range to scan')
    (options, arguments) = parser.parse_args()
    return options

# --------------------------------------------------------
# Code below is for using the Broadcast method
# options = get_arguments()
# result_list = arpScanBroadcast(options.ip_addr)
# print("IP\t\t\tMAC Address\n------------------------------------------------------")
# for i, element in enumerate(result_list[0]):
#     print(result_list[1][i], end='')
#     print("\t\t", end='')
#     print(result_list[0][i])


# ---------------------------------------------------------
# The below code is for using the Unicast method
# options = get_arguments()
# result_list = arpScanUnicast(options.ip_addr)
