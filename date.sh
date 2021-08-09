#!/bin/bash

DATE=2021-01-01
X=" "
for i in {0..366}
do
   NEXT_DATE=$(date +%Y-%m-%d -d "$DATE + $i day")
   X=$(printf "$NEXT_DATE bigtent"| sha256sum)   
   (echo ${X::-3} | gpg --batch --passphrase-fd 0 --armor --decrypt signal.log.gpg) 1>> res.txt 2>>err.txt
done
