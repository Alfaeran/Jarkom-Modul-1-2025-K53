# Node Manwe
wget --no-check-certificate 'https://docs.google.com/uc?export=download&id=11ua2KgBu3MnHEIjhBnzqqv2RMEiJsILY' -O kitab_penciptaan.zip
apt update && apt install unzip -y
unzip kitab_penciptaan.zip


# Node Eru
ftp 10.90.1.1
# login ke ainur
chmod 444 /home/ainur/ftp/kitab_penciptaan.txt
# Capture Wireshark
ftp> get kitab_penciptaan.txt # bisa
ftp> put kitab_penciptaan.txt # tidak bisa