from scapy.all import *
# 2 
etherTypeList = {"ipv4":0x0800,"ipv6":0x86dd,"arp":0x0806}
# 3
ipv4ProtoList = {"tcp":6,"udp":17}
ipv6NextHeader = {"icmp":58,"tcp":6,"udp":17}
# 4
tcpFlags = {
    16: "ACK",
    1: "FIN",
    2: "SYN",
    4: "RST",
    8: "PSH",
    32: "URG",
    64: "ECE",
    128: "CWR",
    3: "SYN FIN"
}
icmpv6Type = {
    1: "Destination Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    4: "Parameter Problem",
    128: "Echo Request",
    129: "Echo Reply",
    130: "Multicast Listener Query",
    131: "Multicast Listener Report",
    132: "Multicast Listener Done",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
    137: "Redirect Message",
    138: "Router Renumbering",
    139: "ICMP Node Information",  
    140: "ICMP Node Response",
    141: "Neighbor Discovery Proximity Triggered",
    142: "Neighbor Discovery Proximity Advertisement"
}

def analysisTCPFlags(inputvalue): #按位与操作，查看tcpFlags是由哪几个bit构成的
    result_flags = []
    for flag_value, flag_name in tcpFlags.items():
        if inputvalue & flag_value != 0:
            result_flags.append(flag_name)
    return " ".join(result_flags)

def tcpApplicationLayerAnalysis(packet,Protocol,Info):
    if packet["TCP"].sport == 443 or packet["TCP"].dport == 443: #TLS
        Protocol = "TLS"
        Info = "TCP Application Data"
    elif packet["TCP"].sport == 80 or packet["TCP"].dport == 80: #HTTP
        Protocol = "HTTP"
        Info = "Application Data"
    elif packet["TCP"].sport == 25 or packet["TCP"].dport == 25: #SMTP
        Protocol = "SMTP"
        Info = "Application Data"
    elif packet["TCP"].sport == 22 or packet["TCP"].dport == 22: #SSH
        Protocol = "SSH"
        Info = "TCP Application Data"
    elif packet["TCP"].sport == 23 or packet["TCP"].dport == 23: #telnet
        Protocol = "telnet"
        Info = "TCP Application Data"
    elif packet["TCP"].sport == 110 or packet["TCP"].dport == 110: #POP3 
        Protocol = "POP3"
        Info = "TCP Application Data"
    elif packet["TCP"].sport == 69 or packet["TCP"].dport == 69: #tftp
        Protocol = "TFTP"
        Info = "TCP Application Data"
    elif packet["TCP"].sport == 21 or packet["TCP"].dport == 21: #ftp control
        Protocol = "FTP Control"
        Info = "TCP Application Data"
    elif packet["TCP"].sport == 20 or packet["TCP"].dport == 20: #ftp data
        Protocol = "FTP Data"
        Info = "TCP Application Data"
    
    return Protocol,Info

def udpApplicationLayerAnalysis(packet,Protocol,Info):
    if packet["UDP"].sport == 1900 or packet["UDP"].dport == 1900: #SSDP
        Protocol = "SSDP"
        Info = "UDP Application Data"
    elif packet["UDP"].sport == 67 or packet["UDP"].dport == 67: # 67,68 DHCP
        Protocol = "DHCP"
        Info = "UDP Application Data" 
    elif packet["UDP"].sport == 68 or packet["UDP"].dport == 68:
        Protocol = "DHCP"
        Info = "UDP Application Data" 
    elif packet["UDP"].sport == 53 or packet["UDP"].dport == 53: # DNS
        Protocol = "DNS"
        Info = "resolve : " + str(packet["DNS"].qd.qname)[2:-1]
    elif packet["UDP"].sport == 80 or packet["UDP"].dport == 80: #HTTP
        Protocol = "HTTP"
        Info = "DUP Application Data"
    return Protocol,Info

def getSummary(packet):

    Source,Destination,Protocol,Length,Info = None,None,None,None,None
    
    if packet["Ether"].type == etherTypeList["ipv4"]:
        Source = packet["IP"].src
        Destination = packet["IP"].dst

        if packet["IP"].proto == ipv4ProtoList["tcp"]:
            Protocol = "TCP"
            # 如果能识别出应用层协议就不显示tcp协议
            Info  = str(packet["TCP"].sport) +"->" +str(packet["TCP"].dport) + " "
            Info += analysisTCPFlags(packet["TCP"].flags) + " SEQ=" + str(packet["TCP"].seq) + " ACK=" + str(packet["TCP"].ack)
            Protocol,Info = tcpApplicationLayerAnalysis(packet, Protocol, Info) # 如果没有识别出应用层协议就原样返回
        elif packet["IP"].proto == ipv4ProtoList["udp"]:
            Protocol = "UDP"
            Info = str(packet["UDP"].sport) +"->" + str(packet["UDP"].dport)
            Protocol,Info = udpApplicationLayerAnalysis(packet, Protocol, Info)
        else:
            print("Exception : unable to identify the packet (IPv4-protocol) , " , packet)

    elif packet["Ether"].type == etherTypeList["ipv6"]:
        Source = packet["IPv6"].src
        Destination = packet["IPv6"].dst

        if packet["IPv6"].nh == ipv6NextHeader["icmp"]:
            Protocol = "ICMPv6"
            Info = icmpv6Type[packet["IPv6"][1].type]
        elif packet["IPv6"].nh == ipv6NextHeader["tcp"]:
            Protocol = "TCPv6"
            Info  = str(packet["TCP"].sport) +"->" +str(packet["TCP"].dport) + " "
            Info += analysisTCPFlags(packet["TCP"].flags) + " SEQ=" + str(packet["TCP"].seq) + " ACK=" + str(packet["TCP"].ack)
            Protocol,Info = tcpApplicationLayerAnalysis(packet, Protocol, Info) # 如果没有识别出应用层协议就原样返回
        elif packet["IPv6"].nh == ipv6NextHeader["udp"]:
            Protocol = "UDP"
            Info = str(packet["UDP"].sport) +"->" + str(packet["UDP"].dport)
            Protocol,Info = udpApplicationLayerAnalysis(packet, Protocol, Info)
        else:
            print("Exception : unable to identify the packet (IPv6-NextHeader) , " , packet)

    elif packet["Ether"].type not in etherTypeList:
        Source = packet["Ether"].src
        Destination = packet["Ether"].dst
        if Source == "ff:ff:ff:ff:ff:ff" or Destination == "ff:ff:ff:ff:ff:ff":
            Info = "BroadCast"

    else:
        print("Exception : unable to identify the packet (Ether-type) , ", packet)
    
    

    Length = len(raw(packet))
    return Source,Destination,Protocol,Length,Info