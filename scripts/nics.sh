#!/bin/bash

# show available interfaces
iw dev | grep -i interface | sed s/.*Interface//

# get input from user
echo There are wlan[num] interfaces. Choose the [num]:
read i

echo Choose id of network to join:
read n

echo Choose host address
read h

# do the magic
ifconfig wlan$i down
iwconfig wlan$i essid mpudp$n mode ad-hoc ap 00:00:00:00:00:0$n
ifconfig wlan$i 192.168.10$n.$h
ifconfig wlan$i up

ifconfig wlan$i down
iwconfig wlan$i essid mpudp$n mode ad-hoc ap 00:00:00:00:00:0$n
ifconfig wlan$i 192.168.10$n.$h
ifconfig wlan$i up

# print results
ifconfig wlan$i
iwconfig wlan$i
