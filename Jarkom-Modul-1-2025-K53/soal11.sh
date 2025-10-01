# Node Melkor
adduser eru
# isi password eru
apt update && apt install openbsd-inetd telnetd -y
nano /etc/inetd.conf
# tambahkan telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/telnetd
service openbsd-inetd restart

# Node Eru
apt update && apt install openbsd-inetd telnetd -y
telnet 10.90.1.2 