import argparse
import sys
import socket
import random
import struct
import json
import argparse

from scapy.all import wrpcap, inet_aton
from scapy.all import Ether, IP, UDP, TCP
from subprocess import call
from pprint import pprint

parser = argparse.ArgumentParser(description='p4apprunner')
parser.add_argument('--output', help='output pcap file.',
                    type=str, action='store', required=True, default='./o.pcap')
parser.add_argument('--config', help='configuration json.',
                    type=str, action='store', required=True, default='./config.json')

args = parser.parse_args()

def inc_ip(ip, max_value):
    ip=struct.unpack("!L", socket.inet_aton(ip))[0]
    ip=(ip+1) & 0xffffffff
    ip2=str(socket.inet_ntoa(struct.pack('!L', ip)))
    return (ip2, ip2==max_value)

def inc_port(port, max_value):
    port = (port+1)&0xffff
    return (port, port==max_value)

def increment(fields, p, max_values, template):
    for f in fields:
        if f=='ip_src':
            p[IP].src, _=inc_ip(p[IP].src, 0)
        elif f=='ip_dst':
            p[IP].dst, _=inc_ip(p[IP].dst, 0)
        elif f=='port_src':
            if p[IP].proto==6:
                p[TCP].sport, _=inc_port(p[TCP].sport, 0)
            else:
                p[UDP].sport, _=inc_port(p[UDP].sport, 0)
        elif f=='port_dst':
            if p[IP].proto==6:
                p[TCP].dport, _=inc_port(p[TCP].dport, 0)
            else:
                p[UDP].dport, _=inc_port(p[UDP].dport, 0)
    return 0

def main():
    with open(args.config) as data_file:
        data = json.load(data_file)

    output=args.output

    flownum=int(data['flownum'])
    template=data['template']
    mac_src=template['mac_src']
    mac_dst=template['mac_dst']
    ip_src=template['ip_src']
    ip_dst=template['ip_dst']
    proto=int(template['proto'])
    port_src=int(template['port_src'])
    port_dst=int(template['port_dst'])
    ranges=data['ranges']

    pktlen=int(data['pktlen'])

    write_batch=100000
    write_list=[]

    pcap_index=0
    if proto==6:
      l4 = TCP(sport=port_src, dport=port_dst)
    else:
      l4 = UDP(sport=port_src, dport=port_dst)
    p = Ether(src=mac_src, dst=mac_dst)/IP(src=ip_src, dst=ip_dst)/ l4 /('0'*(pktlen-42))

    for i in xrange(0, flownum):
        write_list.append(p)
        if i+1 % write_batch==0:
            wrpcap('%s_%d' %(output, pcap_index), write_list)
            write_list.clear()
            pcap_index+=1
        p=p.copy()
        increment(ranges, p, [], template)
        (p[IP].src, _)=inc_ip(p[IP].src, 0)


    if len(write_list)>0:
        wrpcap('%s_%d' %(output, pcap_index), write_list)
        pcap_index+=1

    inputs=""
    for i in range(0, pcap_index):
        inputs+=' %s_%d' %(output, i)

    call(["mergecap -a -w %s %s"% (output, inputs)], shell=True)
    call(["rm %s" % inputs], shell=True)

if __name__ == '__main__':
    main()
