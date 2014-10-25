#!/usr/bin/env python

__author__ = 'Independent Security Evaluators - Chase Schultz'
__version__ = 0.01

__description__ = '''
Bluetooth Low Energy Sniffer - PoC 

Right now it only parses out Advertising Packets. Just needs 
some work on the Scappy Layers to parse other kinds of BTLE packets.
Some development effort is needed possibly. ;)

Data Flow:

USRP -> GNU Radio Companion -> Scapy-Radio -> PCAP

Usage:

python btle_sniff.py -l btle_kevo_sniff.txt -p kevoBlackboxCaputre.pcap -c 100

'''


from scapy.all import *
import logging
import optparse

class BTLESniffer():

	def __init__(self):
		self.logFileName = ''
  
	def printPacketAttrs(self, packet):
		''' Prints Select Packet Fields to stdout '''
		print "Packet Protocol:\t0x%s" % str(packet.proto)
		print "Packet Access Address:\t0x%s" % str(packet.access_addr)
		print "BTLE Advertising Address:\t%s\n" % str(packet.AdvA)
		print "\nPacket Data:\n\n%s\n\n" % str(packet).encode('hex')

	def logPacketAttrs(self, packet):
		''' Propper Logger ... meh '''
		logging.info("Packet Protocol:\t0x%s" % str(packet.proto))
		logging.info("Packet Access Address:\t0x%s" % str(packet.access_addr))
		pass

	def savePacketToFile(self, packet):
		''' Dumps Select Packet Fields to File '''
		packetDump = '\n\n--Advertising Packet--\n\n'
		packetDump += "Packet Protocol:\t0x%s\n" % str(packet.proto)
		packetDump += "Packet Access Address:\t0x%s\n" % str(packet.access_addr)
		packetDump += "BTLE Advertising Address:\t%s\n" % str(packet.AdvA)
		packetDump += "\nPacket Data:\n\n%s\n\n" % str(packet).encode('hex')
		packetDump += '\n--/Advertising Packet--\n\n'
		f = open(self.logFileName , 'a+')
		f.write(packetDump)
		pass

	def handlePacket(self, packet):
		''' Packet Handler '''
		self.printPacketAttrs(packet)
		self.savePacketToFile(packet)
		#Formal Logging Disabled
		#self.logPacketAttrs(packet)
		pass


if __name__ == "__main__":
	#Setup Usage / Version Variables / Proper Logging
	usage = __description__
	version = __version__
	#logging.basicConfig(filename='sniffer.log',level=logging.DEBUG)

	## Banner
	print "\n\n--BTLE Sniffer!--\n\n"

	## Parse Command Line Arguments
	parser = optparse.OptionParser(usage, None, optparse.Option, version)
	parser.add_option('-l', '--logfile', default='btle_sniffer.log',dest='logFileName', help='log file name')
	parser.add_option('-p', '--pcap', default='btle.pcap', dest='pcapFileName', help='pcap file name')
	parser.add_option('-c', '--count', default=50, dest='packetCount', help='number of packets to capture')
	#parser.add_option('-d', '--dump-pcap', default='btle.pcap', dest='pcapDumpFileName', help='pcap file name to dump')
	
	(options, args) = parser.parse_args()

	## instantiate Sniffer / Set Log File
	btleSniffer = BTLESniffer()
	btleSniffer.logFileName = options.logFileName

	#Load the Python Scapy-Radio Module that hooks up to the Gnuradio Packet Sink
	load_module('gnuradio')

	## Capture Specific Number of GNU Radio Ecapsulated Packets
	bluetooth_packets = sniffradio(radio="BT4LE",count=int(options.packetCount))
	
	## Process Packets  ##TODO - Create Pattern for Lamda
	for packet in bluetooth_packets:
		packet.show()
		#hexdump(packet)
		btleSniffer.handlePacket(packet)

	## Write Raw GNURadio traffic to pcap
	wrpcap(options.pcapFileName, bluetooth_packets)
