# scapypktgen
example command:
sudo python gen\_udp.py --output o1.pcap --config config.json


You can replay traffic with [tcpreplay](http://tcpreplay.synfin.net/tcpreplay.html):
for example:
sudo tcpreplay  --preload-pcap -i eth0 --stats=1 --pps=10000 o1.pcap
