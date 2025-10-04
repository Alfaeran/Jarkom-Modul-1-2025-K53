# Jarkom-Modul-1-2025-K53

# Laporan Resmi Modul 1 

## No 1-13

## 1

<img width="924" height="621" alt="image" src="https://github.com/user-attachments/assets/0d98a8aa-dcb7-4274-a0c2-50b9786f7179" />

## 2

### Pada GNS3, klik kanan node eru lalu masuk ke configurations. Setelah itu, klik edit pada network configurations dan masukkan 

```
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
```

## No 14-20

## 14 

### Setelah gagal mengakses FTP, Melkor melancarkan serangan brute force terhadap  Manwe. Analisis file capture yang disediakan dan identifikasi upaya brute force Melkor. 

**Jalankan nc 10.15.43.32 3401 pada terminal**
<br> <img width="550" height="196" alt="image" src="https://github.com/user-attachments/assets/08395c9c-8965-4c4f-80ce-5741d6e5d964" /> </br>

**Download file ZIP pada link drive yang disediakan di soal**
<br> <img width="1571" height="215" alt="image" src="https://github.com/user-attachments/assets/4c6f115e-0d0c-4859-8152-b4c2d3ec928a" /> </br>

**Extract file zip untuk mendapat file pcap**
<br> <img width="739" height="230" alt="image" src="https://github.com/user-attachments/assets/2f9928a1-062b-4d18-b92a-8eecaaffcfe7" /> </br>

**Open pcap file on wireshark**
<br> <img width="554" height="130" alt="image" src="https://github.com/user-attachments/assets/74d44042-dec9-49e9-b74d-3bc8518f8032" /> </br>

**How many packets are recorded in the pcapng file?
Format: int**
<br> <img width="1229" height="908" alt="image" src="https://github.com/user-attachments/assets/5c8fa213-df04-421c-821a-30d8b8858928" /> </br>

by looking down to the footer we can see the information of the amount of the packets

<br> <img width="467" height="67" alt="image" src="https://github.com/user-attachments/assets/f9036f81-deac-4405-a6a3-92a83f500f1d" /> </br>

**What are the user that successfully logged in?
Format: user:pass**

By information from the question we would know that the attacker did bruteforcing, so we can conclude that he try many times to get in and finnally success.

<br> <img width="1229" height="625" alt="image" src="https://github.com/user-attachments/assets/895eb010-230b-40ce-ac32-1cc9bf15d315" /> </br>
From that we can try to search the lattest login with filtering "http" and then scroll down to the lastest.

<br> <img width="944" height="844" alt="image" src="https://github.com/user-attachments/assets/46387a3c-ea2a-4549-93d1-1574db580d05" /> </br>
Try to stream 1 for 1. Then we got the stream that had login successful log in it that contain username:password.
<br> <img width="427" height="71" alt="image" src="https://github.com/user-attachments/assets/6cc5dbc3-e345-474a-9e8c-9476a6b84eb0" /> </br>

**In which stream were the credentials found?
Format: int**
<br> <img width="395" height="65" alt="image" src="https://github.com/user-attachments/assets/2c627537-aefb-40e3-92bd-827443cf5b00" /> </br>

And from that we can got information about the stream that have credentials in it.

**What tools are used for brute force?
Format: Hydra v1.8.0-dev**



For the information of the tools we can get the information too from the stream.
<br> <img width="353" height="114" alt="image" src="https://github.com/user-attachments/assets/f7e199bf-494f-4312-8aae-0c3ac9dc7cb4" /> </br>

and after answering the last question, we will get the flag
<br> <img width="764" height="93" alt="image" src="https://github.com/user-attachments/assets/541b6c9a-9620-474f-bbcc-64cbf9512839" /> </br>
```
Congratulations! Here is your flag: KOMJAR25{Brut3_F0rc3_Ll2Mz7wdI8x9eRf5DDbnINmXZ}
```

## 15 

### Melkor menyusup ke ruang server dan memasang keyboard USB berbahaya pada node Manwe. Buka file capture dan identifikasi pesan atau ketikan (keystrokes) yang berhasil dicuri oleh Melkor untuk menemukan password rahasia.
**Step awal sama seperti sebelumnya !**

**What device does Melkor use?
Format: string**

from the question it self we could know that the device's Melkor use is Keyboard
<br><img width="263" height="64" alt="image" src="https://github.com/user-attachments/assets/4e09a60b-d9e2-4c43-9b87-e3a6c2132fb7" /></br>

**What did Melkor write?
Format: string**

So to know what's Melkor wrote, we try to search "Urb Interrupt in" because we know from the question that melkor stealing password from plug in keyboard usb
<br><img width="731" height="516" alt="image" src="https://github.com/user-attachments/assets/7f15c62d-edb5-49d1-a7c0-6a113d4e6283" /></br>

next we have to decode HID including special char using parsing with python script

First we have to extract HID from pcap file with py script
```c
from scapy.all import rdpcap

packets = rdpcap('hiddenmsg.pcapng')
for i in packets:
    print(i.load[-8:])
```
result:
```c

┌──(Jarvis㉿LAPTOP-LLIIKSKC)-[~/hiddenmsg]
└─$ python3 extract_hid.py
b'\x80\x06\x00\x01\x00\x00\x12\x00'
b'\x84\x00\x00\x01\x01\x02\x00\x01'
b'\x80\x06\x00\x02\x00\x00\t\x00'
b'\x02;\x00\x02\x01\x00\xa0\xf0'
b'\x80\x06\x00\x02\x00\x00;\x00'
b'\x00\x07\x05\x82\x03\x08\x00\x08'
b'\x00\t\x01\x00\x00\x00\x00\x00'
b'\x00\x00\x02\x00\x00\x00\x00\x03'
b'\x0b\x00\x00\xff\x00\x00\x00\x00'
b'\x0b\x00\x00\xff\x00\x00\x00\x00'
b'\x0b\x00\x00\xff\x00\x00\x00\x00'
b'\x0b\x00\x00\xff\x00\x00\x00\x00'
b'\x80\x06\x02\x03\t\x04\x04\x00'
b'\x00\x00\x00\x03\x1a\x03U\x00'
b'\x80\x06\x02\x03\t\x04\x1a\x00'
b'o\x00a\x00r\x00d\x00'
b'\x80\x06\x02\x03\t\x04\x04\x00'
b'\x00\x00\x00\x03\x1a\x03U\x00'
b'\x80\x06\x02\x03\t\x04\x1a\x00'
b'o\x00a\x00r\x00d\x00'
b'!\n\x00\x00\x00\x00\x00\x00'
b'\x00\x00\x02\x00\x00\x00\x00\x03'
b'\x81\x06\x00"\x00\x00w\x00'
b'&\xff\x00\x95\x06\x81\x00\xc0'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'!\n\x00\x00\x01\x00\x00\x00'
b'\x00\x00\x02\x00\x00\x00\x00\x03'
b'\x81\x06\x00"\x01\x00\xcd\x00'
b'\x07\x19h)\x9f\x81\x02\xc0'
b'\x0b\x00\x82\x01\x00\x00\x00\x00'
b'\x0b\x00\x82\x01\x00\x00\x00\x00'
b'\t\x00\x02\x00\x00\x01\x00\x00'
b'\x00\x00\x02\x00\x00\x00\x00\x03'
b'\t\x00\x02\x00\x00\x01\x00\x00'
b'\x00\x00\x02\x00\x00\x00\x00\x03'
b'\t\x00\x02\x00\x00\x01\x00\x00'
b'\x00\x00\x02\x00\x00\x00\x00\x03'
b'\t\x00\x02\x00\x00\x01\x00\x00'
b'\x00\x00\x02\x00\x00\x00\x00\x03'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x18\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\n\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x1b\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00#\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x1b\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00 \x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x05\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x1c\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x10\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x0b\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x1c\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x1b\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x1d\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\n\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x19\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\t\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x08\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x17\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x05\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x1e\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x06\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x0f\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00&\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x1e\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x06\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x1d\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x11\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x1c\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x05\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\r\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x15\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x17\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x1d\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x19\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00%\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b"\x00\x00'\x00\x00\x00\x00\x00"
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x05\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x10\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x15\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\t\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x06\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x07\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x15\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x1d\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x06\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00 \x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x06\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x1a\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x06\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x10\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x14\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x02\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00.\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x0b\x00\x82\x01\x00\x00\x00\x00'
b'\x0b\x00\x82\x01\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x0b\x00\x81\x01\x00\x00\x00\x00'
b'\x0b\x00\x81\xfe\x00\x00\x00\x00'
b'\x0b\x00\x81\xfe\x00\x00\x00\x00'
b'\x0b\x00\x82\xfe\x00\x00\x00\x00'
b'\x0b\x00\x82\xfe\x00\x00\x00\x00'
```
Next we have to make a script to decode
```c
#!/usr/bin/env python3
"""
USB HID Keyboard Decoder
Decode USB HID scan codes from packet capture data
"""

# USB HID Scan Code mappings
lcasekey = {}
ucasekey = {}

# Lowercase and uppercase key mappings
lcasekey[4]="a";   ucasekey[4]="A"
lcasekey[5]="b";   ucasekey[5]="B"
lcasekey[6]="c";   ucasekey[6]="C"
lcasekey[7]="d";   ucasekey[7]="D"
lcasekey[8]="e";   ucasekey[8]="E"
lcasekey[9]="f";   ucasekey[9]="F"
lcasekey[10]="g";  ucasekey[10]="G"
lcasekey[11]="h";  ucasekey[11]="H"
lcasekey[12]="i";  ucasekey[12]="I"
lcasekey[13]="j";  ucasekey[13]="J"
lcasekey[14]="k";  ucasekey[14]="K"
lcasekey[15]="l";  ucasekey[15]="L"
lcasekey[16]="m";  ucasekey[16]="M"
lcasekey[17]="n";  ucasekey[17]="N"
lcasekey[18]="o";  ucasekey[18]="O"
lcasekey[19]="p";  ucasekey[19]="P"
lcasekey[20]="q";  ucasekey[20]="Q"
lcasekey[21]="r";  ucasekey[21]="R"
lcasekey[22]="s";  ucasekey[22]="S"
lcasekey[23]="t";  ucasekey[23]="T"
lcasekey[24]="u";  ucasekey[24]="U"
lcasekey[25]="v";  ucasekey[25]="V"
lcasekey[26]="w";  ucasekey[26]="W"
lcasekey[27]="x";  ucasekey[27]="X"
lcasekey[28]="y";  ucasekey[28]="Y"
lcasekey[29]="z";  ucasekey[29]="Z"
lcasekey[30]="1";  ucasekey[30]="!"
lcasekey[31]="2";  ucasekey[31]="@"
lcasekey[32]="3";  ucasekey[32]="#"
lcasekey[33]="4";  ucasekey[33]="$"
lcasekey[34]="5";  ucasekey[34]="%"
lcasekey[35]="6";  ucasekey[35]="^"
lcasekey[36]="7";  ucasekey[36]="&"
lcasekey[37]="8";  ucasekey[37]="*"
lcasekey[38]="9";  ucasekey[38]="("
lcasekey[39]="0";  ucasekey[39]=")"
lcasekey[40]="\n"; ucasekey[40]="\n"  # Enter
lcasekey[41]="[ESC]";    ucasekey[41]="[ESC]"
lcasekey[42]="[DEL]";    ucasekey[42]="[DEL]"
lcasekey[43]="\t";       ucasekey[43]="\t"  # Tab
lcasekey[44]=" ";        ucasekey[44]=" "   # Space
lcasekey[45]="-";        ucasekey[45]="_"
lcasekey[46]="=";        ucasekey[46]="+"
lcasekey[47]="[";        ucasekey[47]="{"
lcasekey[48]="]";        ucasekey[48]="}"
lcasekey[49]="\\";       ucasekey[49]="|"
lcasekey[50]=" ";        ucasekey[50]=" "
lcasekey[51]=";";        ucasekey[51]=":"
lcasekey[52]="'";        ucasekey[52]="\""
lcasekey[53]="`";        ucasekey[53]="~"
lcasekey[54]=",";        ucasekey[54]="<"
lcasekey[55]=".";        ucasekey[55]=">"
lcasekey[56]="/";        ucasekey[56]="?"
lcasekey[57]="[CAPSLOCK]"; ucasekey[57]="[CAPSLOCK]"

# Raw packet data (last 8 bytes of each packet)
raw_data = """
80060001000012 00
84000001010200 01
80060002000009 00
023b000201 00a0f0
800600020000 3b00
00070582030800 08
00090100000000 00
00000200000000 03
0b0000ff000000 00
0b0000ff000000 00
0b0000ff000000 00
0b0000ff000000 00
80060203090404 00
000000031a0355 00
800602030904 1a00
6f00610072006400
80060203090404 00
000000031a0355 00
800602030904 1a00
6f00610072006400
210a00000000 0000
00000200000000 03
810600220000 7700
26ff0095068100c0
0b008101000000 00
0b008101000000 00
210a00000100 0000
00000200000000 03
8106002201 00cd00
0719682 99f8102c0
0b008201000000 00
0b008201000000 00
09000200000100 00
00000200000000 03
09000200000100 00
00000200000000 03
09000200000100 00
00000200000000 03
09000200000100 00
00000200000000 03
02000000000000 00
0b008101000000 00
02001800000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02000a00000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00001b00000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00002300000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001b00000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00002000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02000500000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00001c00000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02000b00000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001c00000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00001b00000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001d00000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02000a00000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001900000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000900000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000800000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001700000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02000500000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00001e00000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000600000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000f00000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00002600000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00001e00000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000600000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00001d00000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001100000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00001c00000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000500000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000d00000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001500000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00001700000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001d00000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001900000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00002500000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00002700000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000500000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00001000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001500000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000900000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000600000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02000700000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001500000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00001d00000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000600000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00002000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000600000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00001a00000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000600000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00001000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
02001400000000 00
0b008101000000 00
02000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00000000000000 00
0b008101000000 00
00002e00000000 00
"""

def decode_usb_hid():
    """Decode USB HID keyboard data"""
    output = []

    for line in raw_data.strip().split('\n'):
        # Remove spaces and get hex bytes
        hex_data = line.replace(' ', '')

        if len(hex_data) < 4:
            continue

        # Convert to bytes
        try:
            bytes_data = bytes.fromhex(hex_data)

            # Byte 0: modifier keys (0x02 = left shift, 0x20 = right shift)
            # Byte 2: key code
            modifier = bytes_data[0]
            keycode = bytes_data[2] if len(bytes_data) > 2 else 0

            # Check if we have a valid keycode
            if keycode > 3 and keycode < 100:
                # Check if shift is pressed
                if modifier == 0x02 or modifier == 0x20:
                    if keycode in ucasekey:
                        output.append(ucasekey[keycode])
                else:
                    if keycode in lcasekey:
                        output.append(lcasekey[keycode])
        except:
            pass

    return ''.join(output)

if __name__ == "__main__":
    result = decode_usb_hid()
    print("Decoded message:")
    print(result)
    print("\n" + "="*50)
    print("Message length:", len(result))
```
<br>notes!: make sure you put your scirpt at the same directory with pcap file</br>
result:
<br><img width="532" height="155" alt="image" src="https://github.com/user-attachments/assets/b5c9e24b-953c-4a08-a89c-6b439d13bf34" /></br>

So we knew that Melkor Write is:
<br><img width="527" height="76" alt="image" src="https://github.com/user-attachments/assets/d9b2567f-3e61-47c1-bc07-72c0632544f0" /></br>

**What is Melkor's secret message? Format: string**

To see what is Melkor truly write is, we have to convert decode result to string:
<br><img width="978" height="689" alt="image" src="https://github.com/user-attachments/assets/4e40bcf7-0568-4af8-884a-62987ad14d4b" /></br>

Last we input the answer to get the flag:
<br><img width="802" height="97" alt="image" src="https://github.com/user-attachments/assets/8c72bcd1-9faf-4bd6-8357-27609889826c" /></br>

```c
Congratulations! Here is your flag: KOMJAR25{K3yb0ard_W4rr10r_V9IxfCMHIM9BsNAY34P4AN2L4
```
## 16
**Melkor semakin murka ia meletakkan file berbahaya di server milik Manwe. Dari file capture yang ada, identifikasi file apa yang diletakkan oleh Melkor.**
<br>**Step awal sama seperti sebelumnya**</br>

**What credential did the attacker use to log in?
Format: user:pass**

To find Credentials we can try to filter by http,ftp:
<br><img width="1919" height="1016" alt="image" src="https://github.com/user-attachments/assets/3c83ef0d-bc34-436b-bb84-00b5151be47b" /></br>
we can see there is an user and a password:
<br><img width="335" height="48" alt="image" src="https://github.com/user-attachments/assets/593ccc9f-1a78-4c17-9c01-fb1260f349dd" /></br>
now we can answer:
<br><img width="466" height="70" alt="image" src="https://github.com/user-attachments/assets/666181af-f641-4177-a922-0702dd0fbe5a" /></br>

**How many files are suspected of containing malware?
Format: int**

to search information we can try to search it by looking to the down left panel:
<br><img width="474" height="131" alt="image" src="https://github.com/user-attachments/assets/7faea837-415f-4d02-8ad2-26504d7d669f" /></br>
by looking to that we can know that the answer is:
<br><img width="471" height="69" alt="image" src="https://github.com/user-attachments/assets/d02a4625-d709-4912-b46d-92a51a9a5cd6" /></br>

**What is the hash of the first file (q.exe)?
Format: sha256**

To answer this quest we have to travel wireshark to find the file.exe then save it raw and sha256sum to see the hash:
<br><img width="1912" height="288" alt="image" src="https://github.com/user-attachments/assets/4cdde820-2d42-4a41-88c4-4909b6cc8450" /></br>
next,
<br><img width="932" height="840" alt="image" src="https://github.com/user-attachments/assets/5b33023f-da69-4f90-bcc2-65f3621580a8" /></br>
save it!, then
<br><img width="680" height="77" alt="image" src="https://github.com/user-attachments/assets/2047e191-2b74-45c2-8107-d66994170227" /></br>
now, answer it:
<br><img width="614" height="77" alt="image" src="https://github.com/user-attachments/assets/1ddc1387-eb01-49e3-8486-146f88fb5ec9" /></br>

For the next question is same like previous quest we have to find hash for w.exe, e.exe, r.exe, t.exe:

w.exe
<br><img width="610" height="79" alt="image" src="https://github.com/user-attachments/assets/0e75c772-579f-44bb-bea2-3f1705d24558" /></br>

e.exe
<br><img width="614" height="73" alt="image" src="https://github.com/user-attachments/assets/2dc5b5bb-1a82-4ed8-992d-9d94f616fff3" /></br>

r.exe
<br><img width="604" height="76" alt="image" src="https://github.com/user-attachments/assets/60bf1e2f-02f1-4c7c-8d9d-4a09da085796" /></br>

t.exe
<br><img width="875" height="90" alt="image" src="https://github.com/user-attachments/assets/5c9303f0-5876-4523-925e-7e7cf9dd827f" /></br>

and that is the last quest so we get the flag:
```c
Congratulations! Here is your flag: KOMJAR25{Y0u_4r3_4_g00d_4nalyz3r_N9uTF98Yt2wXd1FKlRK3hsdkr}
```
## 17

**Manwe membuat halaman web di node-nya yang menampilkan gambar cincin agung. Melkor yang melihat web tersebut merasa iri sehingga ia meletakkan file berbahaya agar web tersebut dapat dianggap menyebarkan malware oleh Eru. Analisis file capture untuk menggagalkan rencana Melkor dan menyelamatkan web Manwe.**

**Step awal sama seperti sebelumnya!**


For this quest we have to find file.exe so we can do export object by htto to find enable file to export: 
<br><img width="2872" height="1692" alt="image" src="https://github.com/user-attachments/assets/c6431a82-9584-4d57-a53a-03ce2551c29d" /></br>

Look at the Objeclist there's three files that detected at http object list:
<br><img width="1484" height="1057" alt="image" src="https://github.com/user-attachments/assets/476838ed-d79a-43c4-99b3-d069628e1edc" /></br>

now we can answer the question:
<br><img width="994" height="159" alt="image" src="https://github.com/user-attachments/assets/983e6e82-2c3c-442b-99b0-633e79791e88" /></br>

**What is the name of the second suspicious file?
Format: file.exe**

the answer is:
<br><img width="988" height="137" alt="image" src="https://github.com/user-attachments/assets/040f17f4-19d1-4030-95d8-c53cc7997967" /></br>

**What is the hash of the second suspicious file (knr.exe)?
Format: sha256**

To answer this quest, if u still remember the previous numbers walkthrough, you will realize the method is the same.

we export the knr.exe because it's the second file:
<br><img width="1422" height="941" alt="image" src="https://github.com/user-attachments/assets/a854ac6b-55f4-4f94-bc12-1408ce80ff3b" /></br>

To get the hash we use sha256sum:
<br><img width="1491" height="173" alt="image" src="https://github.com/user-attachments/assets/cbc2fcb3-1bc1-451d-ac3e-09da8fd98791" /></br>

The answer is:
<br><img width="1692" height="190" alt="image" src="https://github.com/user-attachments/assets/9ce54aef-67e8-44e9-a127-2a6b30eaaf6d" /></br>

The Flag is:
```c
Congratulations! Here is your flag: KOMJAR25{M4ster_4n4lyzer_IdEUrL1jmETYxG4GDfETyjUrp}
```
## 18

**Karena rencana Melkor yang terus gagal, ia akhirnya berhenti sejenak untuk berpikir. Pada saat berpikir ia akhirnya memutuskan untuk membuat rencana jahat lainnya dengan meletakkan file berbahaya lagi tetapi dengan metode yang berbeda. Gagalkan lagi rencana Melkor dengan mengidentifikasi file capture yang disediakan agar dunia tetap aman.**

**step awal sama seperti sebelumnya**

**How many files are suspected of containing malware?
Format: int**
To solve this quest, same like the previous number we can do export object by SMB:
<br><img width="2879" height="1696" alt="image" src="https://github.com/user-attachments/assets/99596d9c-5d37-4777-b757-781266bcd1ce" /></br>

Export file.exe:
<br><img width="1472" height="1065" alt="image" src="https://github.com/user-attachments/assets/34b5a011-3d18-4f29-9745-39e5cfe89593" /></br>
from this we can see that we had 2 suspicious file:
<br> <img width="1056" height="146" alt="image" src="https://github.com/user-attachments/assets/2f7703e9-5312-47b1-8e9a-fb83a931a8e1" /></br>

**What is the name of the first malicious file?
Format: file.exe**

The answer is:
<br><img width="1407" height="126" alt="image" src="https://github.com/user-attachments/assets/ec75a4b2-fcfe-4a7e-a3e9-7cff6ee15bd9" /></br>

**Apa nama file berbahaya yang kedua?
Format: file.exe**

The answer is:
<br><img width="1388" height="145" alt="image" src="https://github.com/user-attachments/assets/4c4f0bdd-7eab-4a6a-8ceb-4e868bffbbe1" /></br>

**What is the hash of the first malicious file?
Format: sha256**

Use sha256sum to get the hash from file.exe
<br><img width="2838" height="153" alt="image" src="https://github.com/user-attachments/assets/d008801b-350d-4c6c-ae62-f1f02ec2433d" /></br>

The answer is:
<br><img width="1348" height="175" alt="image" src="https://github.com/user-attachments/assets/e01b2140-adda-4a67-863a-d5c2402089cd" /></br>

**What is the hash of the second malicious file?
Format: sha256**

Use sha256sum to get the hash from file.exe
<br><img width="2837" height="158" alt="image" src="https://github.com/user-attachments/assets/1423c865-20e5-4888-83f6-87aacf74b023" /></br>

The Answer is:
<br><img width="1696" height="182" alt="image" src="https://github.com/user-attachments/assets/8f69c141-d2a3-4fb8-96d1-107a70b4d839" /></br>

The flag is:
```c
Congratulations! Here is your flag: KOMJAR25{Y0u_4re_g0dl1ke_l89NvJJPkzaw4mdKGW83YZXFh}
```

## 19

**Manwe mengirimkan email berisi surat cinta kepada Varda melalui koneksi yang tidak terenkripsi. Melihat hal itu Melkor sipaling jahat langsung melancarkan aksinya yaitu meneror Varda dengan email yang disamarkan. Analisis file capture jaringan dan gagalkan lagi rencana busuk Melkor.**

**Langkah awal sama seperti sebelumnya!**

To search for email traffic in Wireshark, focus on specific protocols commonly used for email communication.

Key Protocols:

SMTP (Simple Mail Transfer Protocol): Used for sending emails. Filter by smtp in Wireshark.
POP3 (Post Office Protocol version 3): Used for retrieving emails from a server. Filter by pop or pop3.
IMAP (Internet Message Access Protocol): Also used for retrieving emails, allowing more complex interactions. Filter by imap.

<br><img width="2879" height="1554" alt="image" src="https://github.com/user-attachments/assets/7f2a8e50-871c-4b7d-b9b6-7df7a82cd562" /></br>

Search for suspicious massage:
<br><img width="2879" height="322" alt="image" src="https://github.com/user-attachments/assets/89bc7e3f-a28a-46e5-b82c-aa9764541f69" /></br>

go stream to get information:
<br><img width="2844" height="1691" alt="image" src="https://github.com/user-attachments/assets/7d6eb488-6511-4d09-a139-dc43c865f2e3" /></br>

**Who sent the threatening message?
Format: string (name)**

by the search that we've done, the answer is:
<br><img width="693" height="128" alt="image" src="https://github.com/user-attachments/assets/779bb3da-de2f-4744-b710-2429812ecf8c" /></br>

**How much ransom did the attacker demand ($)?
Format: int**

the answer is:
<br><img width="981" height="128" alt="image" src="https://github.com/user-attachments/assets/ef03deb6-b030-4fb7-9b86-9894900f0694" /></br>

**What is the attacker's bitcoin wallet?
Format: string**

the answer is:
<br><img width="1791" height="217" alt="image" src="https://github.com/user-attachments/assets/54796558-c4da-4521-8a6c-8b9992d4d97a" /></br>

the flag that we get:
```c
Congratulations! Here is your flag: KOMJAR25{Y0u_4re_J4rk0m_G0d_ldwEDOqHBrgLpThYpnVaba7ep}
```

## 20

**Untuk yang terakhir kalinya, rencana besar Melkor yaitu menanamkan sebuah file berbahaya kemudian menyembunyikannya agar tidak terlihat oleh Eru. Tetapi Manwe yang sudah merasakan adanya niat jahat dari Melkor, ia menyisipkan bantuan untuk mengungkapkan rencana Melkor. Analisis file capture dan identifikasi kegunaan bantuan yang diberikan oleh Manwe untuk menggagalkan rencana jahat Melkor selamanya.**

**Step awal sama seperti sebelumnya**

<br><img width="2879" height="1514" alt="image" src="https://github.com/user-attachments/assets/58bfc906-49d6-4ec4-93a1-df468e8d8598" /></br>

from the quest description and wireshark we could know that the file was being encrypted so if u realize when u unzip the file for the quest, we get keylogs for decrypt:
<br><img width="1812" height="699" alt="image" src="https://github.com/user-attachments/assets/ac60a079-e223-4cae-93c5-9f91caa3dac0" /></br>

now use edit by preferences
<br><img width="2302" height="1307" alt="image" src="https://github.com/user-attachments/assets/6ee801ab-61f8-4794-bdfc-a1508e6427df" /></br>

search for tls at protocol
<br><img width="1465" height="1171" alt="image" src="https://github.com/user-attachments/assets/d6ce3e9f-d073-4012-b8b0-904c47427b24" /></br>

and browse master keylog using the file from unzipped file
<br><img width="1377" height="912" alt="image" src="https://github.com/user-attachments/assets/2eeee097-9efd-4e49-9ea5-3ec6cc4c2e1b" /></br>

and xxport objects http to see the file:
<br><img width="1467" height="1038" alt="image" src="https://github.com/user-attachments/assets/44db8076-bc26-4622-b63c-5cdfc42d785d" /></br>

**What encryption method is used?
Format: string**

the answer is: 
<br><img width="624" height="166" alt="image" src="https://github.com/user-attachments/assets/fd223b50-2c76-432d-b0a5-588182a828cd" /></br>

**
What is the name of the malicious file placed by the attacker?
Format: file.exe**

the answer is:
<br><img width="1223" height="129" alt="image" src="https://github.com/user-attachments/assets/f7581fbe-02bc-45f2-8431-47ca351926d6" /></br>

**What is the hash of the file containing the malware?
Format: sha256**

use sha256sum:
<br><img width="1586" height="187" alt="image" src="https://github.com/user-attachments/assets/318e412a-b73b-4d7c-a9db-0ade85f5036b" /></br>
the answer is:
<br><img width="1720" height="197" alt="image" src="https://github.com/user-attachments/assets/aa7d3d20-3085-48e1-83e4-365eeb07bea2" /></br>
the flag is:
```c
Congratulations! Here is your flag: KOMJAR25{B3ware_0f_M4lw4re_FnJynVC0XoZ3EipbqIDdAoUCu}
```
