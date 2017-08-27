# shellcarver v0.1.0
Carve shellcode within the memory using restrictive character set

##Usage: 
python shell_carver.py [4-byte shellcode to carve into memory]
or
./shell_carver.py [4-byte shellcode to carve into memory]

Example:
js@test:~#./shell_carver.py \xaf\x75\xea\xaf
```
Found full match: af75eaaf
\x2d\x01\x01\x03\x01 ;SUB EAX, 0x1030101
\x2d\x01\x31\x09\x01 ;SUB EAX, 0x1093101
\x2d\x4f\x58\x09\x4e ;SUB EAX, 0x4e09584f

Python style string:
"\x2d\x01\x01\x03\x01\x2d\x01\x31\x09\x01\x2d\x4f\x58\x09\x4e"
```
