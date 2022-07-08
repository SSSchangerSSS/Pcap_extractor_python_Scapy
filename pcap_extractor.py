from scapy.all import rdpcap
from time import sleep 
import os
#required classes and functions:__________________________________________________
#for saving packets(using for scanning attacks)
class Scanning_detector:
  def __init__(self, ip, numberOfSyn, numberOfSynAck):
    self.ip = ip
    self.numberOfSyn = numberOfSyn 
    self.numberOfSynAck = numberOfSynAck
#for saving ip packet in file:
def save_ip_pkt(packet_,file_name):
            file_ = open(file_name , "a")
            file_.write(str(packet_.summary())+"\n")
            file_.write('-------------------------------------------------------------------------------'+"\n")
            file_.write("IP HEADER INFO:\n")
            file_.write("version:"+str(packet_['IP'].version)+"\n")
            file_.write("ihl:"+str(packet_['IP'].ihl)+"\n")
            file_.write("tos:"+str(packet_['IP'].tos)+"\n")
            file_.write("len:"+str(packet_['IP'].len)+"\n")
            file_.write("id:"+str(packet_['IP'].id)+"\n")
            file_.write("flags:"+str(packet_['IP'].flags)+"\n")
            file_.write("frag:"+str(packet_['IP'].frag)+"\n")
            file_.write("ttl:"+str(packet_['IP'].ttl)+"\n")
            file_.write("proto:"+str(packet_['IP'].proto)+"\n")
            file_.write("chksum:"+str(packet_['IP'].chksum)+"\n")
            file_.write("src:"+str(packet_['IP'].src)+"\n")
            file_.write("dst:"+str(packet_['IP'].dst)+"\n")
            file_.write('-------------------------------------------------------------------------------'+"\n")
            file_.close()
#for saving tcp packet in file:
def save_tcp_pkt(packet_):
            save_ip_pkt(packet_,filename+"_TCP"+".txt")
            file_ = open(filename+"_TCP"+".txt", "a")
            file_.write("TCP HEADER INFO:\n")
            file_.write("sport:"+str(packet_['TCP'].sport)+"\n")
            file_.write("dport:"+str(packet_['TCP'].dport)+"\n")
            file_.write("seq:"+str(packet_['TCP'].seq)+"\n")
            file_.write("dataofs:"+str(packet_['TCP'].dataofs)+"\n")
            file_.write("ack:"+str(packet_['TCP'].ack))
            file_.write("reserved:"+str(packet_['TCP'].reserved)+"\n")
            file_.write("flags:"+str(packet_['TCP'].flags)+"\n")
            file_.write("window:"+str(packet_['TCP'].window)+"\n")
            file_.write("chksum:"+str(packet_['TCP'].chksum)+"\n")
            file_.write("urgptr:"+str(packet_['TCP'].urgptr)+"\n")
            file_.write("options:"+str(packet_['TCP'].options)+"\n")
            file_.write('-------------------------------------------------------------------------------'+"\n")
            file_.close()
def save_udp_pkt(packet_):
            save_ip_pkt(packet_,filename+"_UDP"+".txt")
            file_ = open(filename+"_UDP"+".txt", "a")
            file_.write("UDP HEADER INFO:\n")
            file_.write("sport:"+str(packet_['UDP'].sport)+"\n")
            file_.write("dport:"+str(packet_['UDP'].dport)+"\n")
            file_.write("len:"+str(packet_['UDP'].len)+"\n")
            file_.write("chksum:"+str(packet_['UDP'].chksum)+"\n")
            file_.write('-------------------------------------------------------------------------------'+"\n")
            file_.close()
def save_icmp_pkt(packet_): 
            save_ip_pkt(packet_,filename+"_ICMP"+".txt")
            file_ = open(filename+"_ICMP"+".txt", "a")
            file_.write("ICMP HEADER INFO:\n")
            file_.write("type:"+str(packet_['ICMP'].type)+"\n")
            file_.write("code:"+str(packet_['ICMP'].code)+"\n")
            file_.write("chksum:"+str(packet_['ICMP'].chksum)+"\n")
            file_.write("reserved:"+str(packet_['ICMP'].reserved)+"\n")
            file_.write("length:"+str(packet_['ICMP'].length)+"\n")
            file_.write("nexthopmtu:"+str(packet_['ICMP'].nexthopmtu)+"\n")
            file_.write("unused:"+str(packet_['ICMP'].unused)+"\n")
            file_.write('-------------------------------------------------------------------------------'+"\n")
            file_.close()
#for saving other packet in file:
def save_other_pkt(packet_):
            file_ = open(filename+"_OTHERS"+".txt", "a")
            file_.write(str(packet_.summary())+"\n")
            file_.write('-------------------------------------------------------------------------------'+"\n")
            file_.close()
#required classes and functions:__________________________________________________
#taking filename as input and show first information:_____________________________
global filename
filename = input('please enter name of file(like trace1) : ')
try:
   #opening pcap file if exist
   a=rdpcap(filename+".pcap")
except Exception:
   print('filename you have entered does not exist')
   exit(0)
#number of all packets with description:   
print(a)
#number of all packets without description:
print("number of packets:"+str(len(a)))
#percent of tcp and udp packets:
b = str(a)
end_=b.index('UDP:')-1
start_=b.index('TCP:')+4
number_of_tcp_packets = float(b[start_:end_])
start_=b.index('UDP:')+4
end_=b.index('ICMP:')-1
number_of_udp_packets = float(b[start_:end_])
start_ = b.index('ICMP:')+5
end_ = b.index('Other:')-1
number_of_icmp_packets = float(b[start_:end_])
start_ = b.index('Other:')+6
end_ = len(b)-1
number_of_other_packets = float(b[start_:end_])
print('percent of tcp packets = %.2f' % (round(number_of_tcp_packets/len(a)* 100 , 2)))
print('percent of udp packets = %.2f' % (round(number_of_udp_packets/len(a)* 100 , 2)))
print('percent of icmp packets = %.2f' % (round(number_of_icmp_packets/len(a)* 100 , 2)))
print('percent of other packets = %.2f' % (round(number_of_other_packets/len(a)* 100 , 2)))

print('-------------------------------------------------------------------------------')  
#a little delay to see first information 
sleep(25)
#taking filename as input and show first information:_____________________________
#VARIABLES:_______________________________________________________________________
#for detecting scannig attack
global syn_
syn_ = 0
global syn_ack
syn_ack = 0
global packet_already_exist_in_list
packet_already_exist_in_list = False
#a list of Scanning_detector class(for detecting scannig attack) 
global record
record = []

#for saving packets in seperate files
global packetIsIp
packetIsIp = False
global packetIsTcp
packetIsTcp = False
global packetIsUcp
packetIsUcp = False
global packetIsIcmp
packetIsIcmp = False

#for detecting active flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

#seperate file for each protocol
global file_TCP
file_TCP = open(filename+"_TCP"+".txt", "w")
global file_UDP
file_UDP = open(filename+"_UDP"+".txt", "w")
global file_ICMP
file_ICMP = open(filename+"_ICMP"+".txt", "w")
global file_OTHERS
file_OTHERS = open(filename+"_OTHERS"+".txt", "w")
global file_ATTACKS
file_ATTACKS = open(filename+"_ATTACKS"+".txt", "w")

file_OTHERS.close()
file_TCP.close()
file_UDP.close()
file_ICMP.close()
#VARIABLES:_______________________________________________________________________


for packet in a:

        packet_already_exist_in_list = False 
        
        packetIsTcp = False
        packetIsUcp = False
        packetIsIcmp = False

        print(packet.summary())
        print('-------------------------------------------------------------------------------') 


        #this (try) will detect ip packets
        try:
            #packet['IP'].show() this line can be used too!
            #if version can not be read exception will happen      
            version = packet['IP'].version
            #IP HEADER INFO:
            print("IP HEADER INFO:")  
            print("version:"+str(version))
            print("ihl:"+str(packet['IP'].ihl))
            print("tos:"+str(packet['IP'].tos))
            print("len:"+str(packet['IP'].len))
            print("id:"+str(packet['IP'].id))
            print("flags:"+str(packet['IP'].flags))
            print("frag:"+str(packet['IP'].frag))
            print("ttl:"+str(packet['IP'].ttl))
            print("proto:"+str(packet['IP'].proto))
            print("chksum:"+str(packet['IP'].chksum))
            print("src:"+str(packet['IP'].src))
            print("dst:"+str(packet['IP'].dst))
            print('-------------------------------------------------------------------------------')  
            if packet.proto == 6:
                  #packet['TCP'].show() this line can be used too!
                  #TCP HEADER INFO:
                  print("TCP HEADER INFO:")
                  print("sport:"+str(packet['TCP'].sport))
                  print("dport:"+str(packet['TCP'].dport))
                  print("seq:"+str(packet['TCP'].seq))
                  print("ack:"+str(packet['TCP'].ack))
                  print("dataofs:"+str(packet['TCP'].dataofs))
                  print("reserved:"+str(packet['TCP'].reserved))
                  print("flags:"+str(packet['TCP'].flags))
                  print("window:"+str(packet['TCP'].window))
                  print("chksum:"+str(packet['TCP'].chksum))
                  print("urgptr:"+str(packet['TCP'].urgptr))
                  print("options:"+str(packet['TCP'].options))
                  packetIsTcp = True
                  syn_ack = 0
                  syn_ = 0

                  F = packet['TCP'].flags    # this should give you an integer
                  if F & FIN:
                         print('FIN flag activated')
                  if F & SYN:
                         print('SYN flag activated')
                         syn_ = 1    
                  if F & RST:
                         print('RST flag activated')
                  if F & PSH:
                         print('PSH flag activated')   
                  if F & ACK:
                         print('ACK flag activated')
                  if F & URG:
                         print('URG flag activated')  
                  if F & ECE:
                         print('ECE flag activated')  
                  if F & CWR:
                         print('CWR flag activated')
                  if F & SYN and F & ACK:
                         syn_ack = 1
          
                  for r in record:
                     if r.ip == packet['IP'].src:
                            packet_already_exist_in_list = True
                            r.numberOfSyn += syn_
                            r.numberOfSynAck += syn_ack

                  if packet_already_exist_in_list == False:                    
                            record.append(Scanning_detector(packet['IP'].src,syn_,syn_ack))
                  
                  print('-------------------------------------------------------------------------------')  

            elif packet.proto == 17:
                  #packet['UDP'].show() this line can be used too!
                  #UDP HEADER INFO:
                  print("UDP HEADER INFO:")
                  print("sport:"+str(packet['UDP'].sport))
                  print("dport:"+str(packet['UDP'].dport))
                  print("len:"+str(packet['UDP'].len))
                  print("chksum:"+str(packet['UDP'].chksum))
                  packetIsUcp = True
                  print('-------------------------------------------------------------------------------')  
                  
              
        
            try:
              #packet['ICMP'].show() this line can be used too!
              #if type can not be read exception will happen 
              type_ = packet['ICMP'].type
              #ICMP HEADER INFO:
              print("ICMP HEADER INFO:")
              print("type:"+str(type_))
              print("code:"+str(packet['ICMP'].code))
              print("chksum:"+str(packet['ICMP'].chksum))
              print("reserved:"+str(packet['ICMP'].reserved))
              print("length:"+str(packet['ICMP'].length))
              print("nexthopmtu:"+str(packet['ICMP'].nexthopmtu))
              print("unused:"+str(packet['ICMP'].unused))
              packetIsIcmp = True
              print('-------------------------------------------------------------------------------')  

            except Exception:
               #packet is not icmp  
               pass



            #saving packets to seperate files
            if packetIsTcp == True:
              save_tcp_pkt(packet)
            if packetIsUcp == True:
              save_udp_pkt(packet)
            if packetIsIcmp == True:
              save_icmp_pkt(packet)


            #packet is not ip
        except Exception:
            #saving packet to Others
            save_other_pkt(packet)
            continue    

file_ATTACKS = open(filename+"_ATTACKS"+".txt", "a")
for r in record:
    #print("ip:"+str(r.ip)+" num_syn:"+str(r.numberOfSyn)+" num_syn_ack:"+str(r.numberOfSynAck))   
    if (r.numberOfSyn - r.numberOfSynAck)/3 >= 1:
           print("ip:"+str(r.ip)+" num_syn:"+str(r.numberOfSyn)+" num_syn_ack:"+str(r.numberOfSynAck) + " ***warning => Scanning***")
           file_ATTACKS.write("ip:"+str(r.ip)+" num_syn:"+str(r.numberOfSyn)+" num_syn_ack:"+str(r.numberOfSynAck) + " ***warning => Scanning***"+"\n")
           file_ATTACKS.write('-------------------------------------------------------------------------------'+"\n")
file_ATTACKS.close()
