from scapy.all import * 
packets = rdpcap('cash.cap') # 'example.pcap' 是 pcap 文件名 
# for packet in packets:
#     # 可以通过 packet.show() 打印每个数据包的详细信息
#     # 这里演示如何获取数据包的源地址和目标地址
#     # src = packet['IP'].src
#     # dst = packet['IP'].dst
#     # print(f'Source IP: {src}, Destination IP: {dst}')
#     #print(hexdump(packet))
#     #print(EtherDA(packet))
#     packet.show()
#ackets[0].show()
#packets[0].show2()
#print(hexdump(packets[0]))
#print(packets[0]["Ether"].src)
#print(packets[0]["UDP"])

