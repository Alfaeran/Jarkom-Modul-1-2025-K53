# Node Eru
apt update && apt install openssh-server
service ssh start
service ssh enable

# Node Varda
echo nameserver 192.168.122.1 > /etc/resolv.conf
apt update && apt install openssh-server
ssh eru@10.90.1.1