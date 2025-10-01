# klik kanan node eru di GNS3 lalu masuk ke configurations
# klik edit pada network configurations

auto eth0
iface eth0 inet dhcp

auto eth1
iface eth1 inet static
	address 10.90.1.1
	netmask 255.255.255.0

auto eth2
iface eth2 inet static
	address 10.90.2.1
	netmask 255.255.255.0

# Saya memakai VMware kali linux
apt update && apt install iptables -y
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE -s 10.90.0.0/16

#untuk melkor, manwe, varda, ulmo
echo "nameserver 192.168.122.1" > /etc/resolv.conf