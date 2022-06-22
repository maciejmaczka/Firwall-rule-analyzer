#!/usr/bin/python

import os
import socket
import struct


try: 
    os.mkdir("blackwall") 
except OSError as error: 
    print(error)  



print("Gathering facts ....")
print("Dynamic Objects")

os.system("dynamic_objects -l > blackwall/dynamic_objects.swa")

print("Updatable Objects")
os.system("dynamic_objects -uo_show > blackwall/updatable_objects.swa")

print("Identity Awareness")
os.system('pdp monitor all | grep "Session:\|Groups:\|Roles:\|Client Type:" > blackwall/identity_awareness.swa')

print("Domain Objects")
os.system('cat $FWDIR/state/local/FW1/local.domain | grep "name" > blackwall/domain_objects.tmp')

with open("blackwall/domain_objects.tmp") as f:
    content = f.readlines()


os.system(' echo "" >  blackwall/domain_objects.swa ' )

prev_line = ""

for line in content:
	try:
		#print(line)
		line = line.replace(":name", "")
		line = line.replace("(.", "")
		line = line.replace(")","")
		line = line.replace("\t", "")
		
		if (prev_line == line):
			continue

		prev_line = line
		command = 'domains_tool -d  '  + line + ' -m  >> blackwall/domain_objects.swa'
		command = command.replace("\n", "")
		#print(command)		
		os.system(command)
	except ValueError as error:
		print("Some Error")


os.remove("blackwall/domain_objects.tmp")


