netsh interface ipv4 set address name="wintun" source=static addr=192.168.86.86 mask=255.255.255.0
netsh interface ipv4 set dnsservers name="wintun" static address=192.168.43.1 register=none validate=no
netsh interface ipv4 add route 0.0.0.0/0 "wintun" 192.168.86.86 metric=1

rem 里面的 ip 地址根据你们的实际情况修改：