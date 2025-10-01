# Node Ulmo
wget --no-check-certificate 'https://docs.google.com/uc?export=download&id=11ra_yTV_adsPIXeIPMSt0vrxCBZu0r33' -O cuaca.zip
apt update && apt install unzip -y
unzip cuaca.zip
ftp 10.90.1.1
put cuaca.txt
put mendung.jpg