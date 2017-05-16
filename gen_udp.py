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

def inc_ip(ip, max_value, initial):
    ip=struct.unpack("!L", socket.inet_aton(ip))[0]
    ip=(ip+1) & 0xffffffff
    ip2=str(socket.inet_ntoa(struct.pack('!L', ip)))
    if ip2==max_value:
      return (ip2, 1)
    return (ip2, 0)

def inc_port(port, max_value, initial):
    port = (port+1)&0xffff
    if port==max_value:
      return (initial, 1) 
    return (port, 0)

def increment(fields, p, max_values, template):
    m = 1
    for f in fields:
        if f=='ip_src':
            p[IP].src, m=inc_ip(p[IP].src, max_values['ip_src'], template['ip_src'])
        elif f=='ip_dst':
            p[IP].dst, m=inc_ip(p[IP].dst, max_values['ip_dst'], template['ip_dst'])
        elif f=='port_src':
            if p[IP].proto==6:
                p[TCP].sport, m=inc_port(p[TCP].sport, int(max_values['port_src']), int(template['port_src']))
            else:
                p[UDP].sport, m=inc_port(p[UDP].sport, int(max_values['port_src']), int(template['port_src']))
        elif f=='port_dst':
            if p[IP].proto==6:
                p[TCP].dport, m=inc_port(p[TCP].dport, int(max_values['port_dst']), int(template['port_dst']))
            else:
                p[UDP].dport, m=inc_port(p[UDP].dport, int(max_values['port_dst']), int(template['port_dst']))
        if m==0:
          return 0
    return m

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
    ranges=data['ranges'].keys()
    max_values={}
    for r in ranges:
      max_values[r]=data['ranges'][r]['max']

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
        increment(ranges, p, max_values, template)


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
