# Node Eru

apt update
apt install vsftpd -y && apt install ftp -y
adduser ainur
adduser melkor
mkdir -p /home/ainur/ftp/shared
chown -R ainur:ainur /home/ainur/ftp/shared/
mkdir -p /home/melkor/ftp/shared
chown -R root:root /home/melkor/ftp/shared/
chmod 755 /home/melkor/ftp/shared/
pkill vsftpd
service vsftpd start
ftp localhost



# edit confignya
cat <<EOF > /etc/vsftpd.conf
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
user_sub_token=$USER
local_root=/home/$user/ftp
userlist_enable=YES
userlist_file=/etc/vsftpd.user_list
userlist_deny=YES
EOF

# Masukkin file bebas ke folder shared
echo "p" > /shared/test.txt
echo "p" > /root/tes.txt
service vsftpd start
ftp 10.90.1.1
# login ke ainur
ftp> binary
ftp> get test.txt
ftp> put tes.txt
# login pake user melkor