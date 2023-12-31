from scapy.all import *
# 2 层
etherTypeList = {"ipv4":0x0800,"ipv6":0x86dd,"arp":0x0806}
# 3 层
ipv4ProtoList = {"tcp":6,"udp":17}
ipv6NextHeader = {"icmp":58,"tcp":6,"udp":17}
# 4 层
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
    if "Ether" not in packet:
        Source = ""
        Destination = ""
        Protocol = "Ether"
        Info = "Ethernet Packet"
        
    elif packet["Ether"].type == etherTypeList["ipv4"]:
        Source = packet["IP"].src
        Destination = packet["IP"].dst

        if packet["IP"].proto == ipv4ProtoList["tcp"]:
            Protocol = "TCP"
            # 如果能识别出应用层协议就不显示tcp协议
            if "Raw" in packet:
                Protocol,Info = tcpApplicationLayerAnalysis(packet, Protocol, Info) # 如果没有识别出应用层协议就原样返回
            else:
                Info  = str(packet["TCP"].sport) +"->" +str(packet["TCP"].dport) + " "
                Info += analysisTCPFlags(packet["TCP"].flags) + " SEQ=" + str(packet["TCP"].seq) + " ACK=" + str(packet["TCP"].ack)
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
            if "Raw" in packet:
                Protocol,Info = tcpApplicationLayerAnalysis(packet, Protocol, Info) # 如果没有识别出应用层协议就原样返回
            else:
                Info  = str(packet["TCP"].sport) +"->" +str(packet["TCP"].dport) + " "
                Info += analysisTCPFlags(packet["TCP"].flags) + " SEQ=" + str(packet["TCP"].seq) + " ACK=" + str(packet["TCP"].ack)
        elif packet["IPv6"].nh == ipv6NextHeader["udp"]:
            Protocol = "UDP"
            Info = str(packet["UDP"].sport) +"->" + str(packet["UDP"].dport)
            Protocol,Info = udpApplicationLayerAnalysis(packet, Protocol, Info)
        else:
            print("Exception : unable to identify the packet (IPv6-NextHeader) , " , packet)

    elif packet["Ether"].type ==etherTypeList["arp"]:
        Protocol = "ARP"
        if packet["ARP"].op == 1:
            Info = "ARP Who has " + packet["ARP"].pdst
        elif packet["ARP"].op == 2:
            Info = "ARP Reply " + packet["ARP"].psrc
        else:
            Info = "ARP Packet"

    elif packet["Ether"].type not in etherTypeList:
        Source = packet["Ether"].src
        Destination = packet["Ether"].dst
        if Source == "ff:ff:ff:ff:ff:ff" or Destination == "ff:ff:ff:ff:ff:ff":
            Info = "BroadCast"

    else:
        print("Exception : unable to identify the packet (Ether-type) , ", packet)
    
    

    Length = len(raw(packet))
    return Source,Destination,Protocol,Length,Info

def getTreeInfo(packet):
    tree = []
    if "Ether" in packet:
        EtherSrc = packet["Ether"].src
        EtherDst = packet["Ether"].dst
        EtherType = packet["Ether"].type
        tree.append("Ether Layer : \n\tdst={} \n\tsrc={} \n\ttype={}".format(EtherSrc,EtherDst,EtherType))
    if "IP" in packet :
        tree.append("IP Layer : \n\tversion={}\n\tihl={}\n\ttos={}\n\tlen={}\n\tid={}\n\tflag={}\n\tfrag={}\n\tttl={}\n\tproto={}\n\tchecksum={}\n\tsrc={}\n\tdst={}".format(str(packet["IP"].version),str(packet["IP"].ihl),str(packet["IP"].tos),str(packet["IP"].len),str(packet["IP"].id),str(packet["IP"].flags),str(packet["IP"].frag),str(packet["IP"].ttl),str(packet["IP"].proto),str(packet["IP"].chksum),str(packet["IP"].src),str(packet["IP"].dst)))
    if "ARP" in packet:
        tree.append("ARP Layer : \n\thwtype={}\n\tptype={}\n\thwlen={}\n\tplen={}\n\top={}\n\thwsrc={}\n\tpsrc={}\n\thwdst={}\n\tpdst={}".format(str(packet["ARP"].hwtype),str(packet["ARP"].ptype),str(packet["ARP"].hwlen),str(packet["ARP"].plen),str(packet["ARP"].op),str(packet["ARP"].hwsrc),str(packet["ARP"].psrc),str(packet["ARP"].hwdst),str(packet["ARP"].pdst)))
    if "ICMP" in packet:
        tree.append("ICMP Layer : ")
    if "TCP" in packet:
        tree.append("TCP Layer : \n\tsport={}\n\tdport={}\n\tseq={}\n\tack={}\n\tdataofs={}\n\treserved={}\n\tflaags={}\n\twindow={}\n\tchecksum={}\n\turgptr={}".format(str(packet["TCP"].sport),str(packet["TCP"].dport),str(packet["TCP"].seq),str(packet["TCP"].ack),str(packet["TCP"].dataofs),str(packet["TCP"].reserved),str(packet["TCP"].flags), str(packet["TCP"].window),str(packet["TCP"].chksum),str(packet["TCP"].urgptr)))
    if "UDP" in packet:
        tree.append("UDP Layer : ")
    if "Raw" in packet:
        tree.append("Application Layer : \n\t" + str(packet["Raw"].load))
    return tree
    
