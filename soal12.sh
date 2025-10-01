# Node Melkor
apt update && apt install vsftpd -y
apt install apache2
service vsftpd start # port 21
service apache2 start # port 80

#Node Eru
nc -zv 10.90.8.2 21 80 666