#!/usr/bin/python
# Project initialised by Kloer
# Maintained by Kloer & drkn
import socket, sys 
from struct import *
from scapy.all import *
from scapy.utils import PcapWriter

def readKeys():
	keys = []
	with open("tables/twRO/keys.txt") as f:
		for line in f:
			if '#' not in line:
				keys.append(int(line.strip(), 16))
	return keys

def readMapLogin():
	with open("tables/twRO/shuffles.txt") as f:
		for line in f:
			if 'map_login' in line:
				return int(line[:4], 16)

def hex(i):
	return '0x%04x' % i
				
print "-------------------------------------"
print "-    RO Packet Decoding Script    -"
print "-------------------------------- ----"

if len(sys.argv) < 3: #No args/not enough args
	print "[*] Usage: ./ropcap.py <encrypted.pcap> <decrypted.pcap>"
	exit()

serverIPFilter = '218.32.4.' #twRO
loginMapFound = False

# calculate pattern that indicate the starting point of key xoring
cryptoKey = readKeys() #Defining crypto keys
mapLoginID = readMapLogin()
cryptoSelection = 0 #Using the 1st one of the key by default
firstKey = cryptoKey[cryptoSelection] * cryptoKey[2] + cryptoKey[1] & 0xFFFFFFFF
shiftedKey = (firstKey >> 16) & 0x7FFF
mapLoginID_encrypted = (mapLoginID ^ shiftedKey) & 0xFFFF


oldPcap = sys.argv[1]
newPcap = sys.argv[2]

outputPcapFile = open(newPcap, 'wb')


# outputPcap = dpkt.pcap.Writer(outputPcapFile)

# Getting packets
packets = rdpcap(oldPcap)
pcapWriter = PcapWriter(newPcap, append=False, sync=True)
mapPackets = []

#Now parsing every line
for single in packets:
	#Not RO traffic
	# if serverIPFilter not in single[IP].src and serverIPFilter not in single[IP].dst:
		# packets.remove(single)
		# continue
	
	if single[TCP].dport in range(10000,10100) and single[TCP].payload: #From server and has data
		header = single[TCP].payload.load[:2]
		
		messageID = ord(header[0]) | ord(header[1]) << 8
		if messageID == mapLoginID_encrypted:
			print ('Found map_loing packet, start xoring crypt key')
			loginMapFound = True #Initial starting key
			#$self->{encryption}->{crypt_key} = $self->{encryption}->{crypt_key_1};
			crypt_key = cryptoKey[0]
		if not loginMapFound:
			pcapWriter.write(single)
			continue
			
		#my $oldMID = $messageID;
		oldMID = messageID
		# ######## update key
		#my $oldKey = ($self->{encryption}->{crypt_key} >> 16) & 0x7FFF;
		oldKey = (crypt_key >> 16) & 0x7FFF
		
		#$self->{encryption}->{crypt_key} = ($self->{encryption}->{crypt_key} * $self->{encryption}->{crypt_key_3} + $self->{encryption}->{crypt_key_2}) & 0xFFFFFFFF;
		crypt_key = crypt_key * cryptoKey[2] + cryptoKey[1] & 0xFFFFFFFF
		# restore original messageID
		#$messageID = ($messageID ^ (($self->{encryption}->{crypt_key} >> 16) & 0x7FFF)) & 0xFFFF;
		messageID = ((messageID ^ (crypt_key >> 16)) & 0x7FFF) & 0xFFFF
		
		print "Key: [" + str(hex(oldKey)[:6].upper()) + "]->[" + str(hex(crypt_key)[:6].upper()) + "]"
		print  "Decrypt: [" + str(hex(unpack('H2', header)[0])).upper()[:4] + "]->[" + str(hex(messageID)).upper()[:4] + "]"
		hexdump(header)
		hexdump(pack('H2', messageID))
		# raw_input()
		
		single[TCP].payload.load = str(pack('H2', messageID)) + single[TCP].payload.load[2:]
	pcapWriter.write(single)
			
print 'Parse done'
