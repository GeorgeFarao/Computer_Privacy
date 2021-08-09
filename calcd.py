import math

flag=0
for i in range(1,1000000):
	if (7*i)%1276700779==1:
        print i
        flag=1
if flag==0:
    print("Not Found!")