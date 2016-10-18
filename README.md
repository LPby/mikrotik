##Mikrotik shaper script

Add prioritized IPs to list:
```bash
/ip firewall address-list
add address=192.168.1.10 list=Users
add address=192.168.1.11 list=Users
```
add queue type:
```bash
/queue type
add kind=pcq name=download pcq-burst-time=5s pcq-classifier=dst-address pcq-dst-address6-mask=64 pcq-src-address6-mask=64
add kind=pcq name=upload pcq-burst-time=1s pcq-classifier=src-address pcq-dst-address6-mask=64 pcq-src-address6-mask=64
```
make settings changes.

and run provided script.

