#! /usr/bin/env python
#from scapy import *
try:
	import sys
	import logging
	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
	from scapy.all import *
	import re
	import os
	import string
	import argparse
	import fileinput
	import types
except:
	sys.stderr.write("ERROR: nepodarilo se importovat vsechny potrebne knihovny\n")
	exit(1)


# napoveda
def napoveda ():
	napoveda = """\n\t======================== [ NAPOVEDA PROGRAMU ] ==================================
	|\t
	|\tVitejte v napovede programu SIPSCAN do predmetu ISA
	|\tAutor: Tomas Slunsky, xsluns01@stud.fit.vutbr.cz
	|\t
	|\t[ UZITI ]
	|\t	./sipscan.py {-f|-i} name -o file [-p number] 
	|\t	
	|\t[ PARAMETRY ]
	|\t-f [--file] name -- data pro analyzu se ziskaji ze souboru formatu pcap
	|\t-i [--interface] name -- data sa odchyti z rozhrani zo zadanym nazvom
	|\t-o [--output] file -- vysledky sa zapisu do souboru so zadanym nazvom
	|\t-p [--port] num -- cislo portu na kterem probiha signalizacea SIP 
	|
	=================================================================================\n"""
	return napoveda

# err report
def error(msg,errcode):
	sys.stderr.write("ERROR: "+msg+"\n")
	exit(errcode)


#regexp: load\s*=\s*[\'\"][^\'\"]+[\'\"] 
sys.stdout = open('data.txt', 'w')


# vytrovani protokolu
def filter (file, port):

	# jake porty filtrovat
	if type(port) is list:
		ports = port
	elif type(port) is int:
		ports = [port]
	else:
		error("spatny port",1)

	# vystupni soubor
	if os.path.isfile(file) and os.access(file, os.R_OK):
		pkts = rdpcap(file)   
	else:
		error("Soubor neexistuje, nebo neni citelny",2)

	# jake protokoly filtrovat
	protocols = [UDP,TCP,RTP] 

	# prochazim paket po paketu
	for pkt in pkts:
		for protocol in protocols: 												 # prochazim filtrovane protokoly
			if protocol in pkt:													 #zjistuju zdali je dany paket daneho protokolu
				if pkt[protocol].sport in ports or pkt[protocol].dport in ports: #zjistuju zdali je dany paket daneho protokolu
					print pkt.show()


# vyparsovani dulezitych dat z paketu register
def registerParse(pkt):
	return True

# vyparsovani dulezitych dat z paketu invite
def pktParser(pkt):
	if pkt.haslayer(Raw):
		# nacteni obsahu paketu
		load = repr(pkt[Raw].load)

		# ODSTRRANENI \'
		pkt = load.replace("'","") 

		# init
		invitePacked = {}

		# zpracovani paketu
		uri   	   = re.search(r"(?<=uri\=[\"\'])\s*[^\"]+(?=\")", pkt)
		in_uri     = re.search(r"(?<=in_uri\=sip:)[^\@]+@[\w\.\-\_\:]+(?=\s)", pkt)
		out_uri    = re.search(r"(?<=out_uri\=sip:)[^\@]+@[\w\.\-\_\:]+(?=\s)", pkt)
		bye   	   = re.search(r"(?<=BYE\ssip:)\s*[^\s]+(?=\s)", pkt)
		ack   	   = re.search(r"(?<=ACK\ssip:)\s*[^\s]+(?=\s)", pkt)
		register   = re.search(r"(?<=REGISTER\ssip:)\s*[^\s]+(?=\s)", pkt)
		invite     = re.search(r"(?<=INVITE\ssip:)[\w]+@[\w]+.[a-zA-Z]+", pkt)
		udp        = re.search(r"(?<=UDP\s)[\w\.]+(?=;)", pkt)
		to         = re.search(r"(?<=[tT][oO]:\s)([\w\s]+)?<[^>]+>", pkt)
		fromP      = re.search(r"(?<=From:\s)([\"\'\w\s]+)?<[^>]+>", pkt)
		contact    = re.search(r"(?<=Contact:\s)([\"\'\w\s]+)?<[^>]+>", pkt)
		callid     = re.search(r"(?<=Call-ID:\s)[\"\'\w\s\-]+@[\"\'\w\s\-\.]+(?=[\\\s])", pkt)
		branch     = re.search(r"(?<=branch=)\s*[\"\'\w\s\-\.]+(?=[\\\s])", pkt)

		# nahazeni do slovniku
		if register is not None: invitePacked["register"] 	= register.group(0)
		if invite 	is not None: invitePacked["invite"] 	= invite.group(0)
		if ack 	 	is not None: invitePacked["ack"] 		= ack.group(0)
		if bye 		is not None: invitePacked["bye"] 		= bye.group(0)
		if udp 		is not None: invitePacked["udp"] 		= udp.group(0)
		if to 		is not None: invitePacked["to"] 		= to.group(0)
		if fromP 	is not None: invitePacked["from"] 		= fromP.group(0)
		if contact  is not None: invitePacked["contact"]	= contact.group(0)
		if callid   is not None: invitePacked["call-id"]	= callid.group(0)
		if uri 		is not None: invitePacked["uri"] 		= uri.group(0)
		if in_uri 	is not None: invitePacked["in_uri"]		= in_uri.group(0)
		if out_uri 	is not None: invitePacked["out_uri"]	= out_uri.group(0)
		if branch 	is not None: invitePacked["branch"]		= branch.group(0)

		#navrat
		return invitePacked
	return False

# overeni protokoli a portu
def checkProtocolAndPort (pkt,protocols,port):
	# jake porty filtrovat
	if type(port) is list:
		ports = port
	elif type(port) is int:
		ports = [port]
	else:
		error("spatny port",1)

	# check
	for protocol in protocols: 												 # prochazim filtrovane protokoly
		if protocol in pkt:													 # zjistuju zdali je dany paket daneho protokolu
			# jeste treba zjistit, jestli tam ma byt and										 
			if pkt[protocol].sport in ports or pkt[protocol].dport in ports: # zjistuju zdali je dany paket daneho protokolu
				return True
			else:
				return False
		else:
			False

# vyparsovani vsech paketu ze SIP zprava z paketuu pcap souboru
def filter2 (file, port=5060, bymsg=1):

	# vystupni soubor
	if os.path.isfile(file) and os.access(file, os.R_OK):
		pkts = rdpcap(file)   
	else:
		error("Soubor neexistuje, nebo neni citelny",2)

	# jake zpravy a protokoly filtrovat
	messages = ["SIP","INVITE","ACK","BYE","REGISTER","CANCEL","REFER","OPTIONS","INFO"] 
	protocols = [TCP,UDP,SCTP] # nad jakejma protokolama vetsinou bezi SIP

	# navratove pole
	retlist = []
	
	# prochazim paket po paketu
	for pkt in pkts:
		# filtr, ktery vyhodi jine pakate nez na povolenych protokolech a portech
		if not checkProtocolAndPort(pkt,protocols,port):
			#continue
			pass
		
		# samotna zprava paketu se nahraje do pole
		if pkt.haslayer(Raw):
			# nacteni obsahu paketu
		 	load = repr(pkt[Raw].load)
		 	# projit zpravy po zprave
		 	for message in messages:
		 		# orezani od apostrofu
		 		load = load.replace("'","")
		 		#zjisteni zdali se jedna o paket sip 
		 		if re.match(r'^'+message,load):
		 			# v pripade ze ani, pridam ho do vysledneho pole
		 			retlist.append(pkt) # retlist.append(load)
		 			break # nactu dalsi paket
	return retlist


# zjisteni typu paketu: 2 typy
def getPktType (pkt):
	if pkt.haslayer(Raw):
		# nacteni obsahu paketu
		load = repr(pkt[Raw].load)

		# ODSTRRANENI \'
		pkt = load.replace("'","") 

		# typy zprav
		messages = ["INVITE","ACK","BYE","REGISTER","CANCEL"] #,"REFER","OPTIONS","INFO"

		# zjistim o jaky typ paketu se jedna
		# 1=POZADAVEK
		# 2=ODPOVED na pozadavek
		if re.match(r'^SIP\/[0-9]+\.[0-9]+\s[0-9]{3,3}',pkt):
			return 2
		for msg in messages:
			#if msg in pkt:
			if re.match(r'^'+msg,pkt):
				return 1
		return False
	else:
		return False

# vyparsovani navratoveho kodu z paketu
def getAnswer(pkt):
	if pkt.haslayer(Raw):
		# nacteni obsahu paketu
		load = repr(pkt[Raw].load)

		# ODSTRRANENI \'
		pkt = load.replace("'","") 

		# vyprasuju z paketu SIP s verzi a navratovym kodem
		match = re.search(r"SIP\/[0-9]+\.[0-9]+\s[0-9]{3,3}", pkt)
		if match is None:
			return False
		else:
			# pokud ho najdu, vyparsuju z nej samotnou prvni cislici a prevedu na int
			match_int = re.search(r"(?<=\s)[0-9]{3,3}", match.group(0))
			if match_int is not None:
				num_of_answer = match_int.group(0)
				return int(num_of_answer[0:1]) ## vracim prvni cislo chyby
			else:
				return False
	else:
		return False

# overi zdali je v paketu zprava na zacatku
def pktSearch(pkt,msg):
	if pkt.haslayer(Raw):
		# nacteni obsahu paketu
		load = repr(pkt.load) #repr(pkt[Raw].load)

		# ODSTRRANENI \'
		pkt = load.replace("'","")

		if re.match(r'^'+msg,pkt):
			return True
		else:
			return False 
	else:
		return False 

# overi zdali se v nasledujicih paketech vyskytuje nejakY SIP REQUEST
def pktReqSearch(pkts,req):
	for index in range (len(pkts)):
		if pktSearch(pkts[index],req):
			return True
	return False

# vyhodnoceni Paketu
def executePkts(pkts):
	# navratove pole
	retlist = []
	tmplist = []
	registers = []
	newret  = []
	data = {}
	#data[el][prefix+el+sufix]=pk
	#data[el]={prefix+el+sufix:pk}
	zacatek_hovoru = 0 # prvni invite

	# zpracovani hovoru
	for index in range (len(pkts)):
		if pkts[index]:
			#print pkts[index].show()
			print index
			print pkts[index].load

			if pktSearch(pkts[index],"REGISTER"):
				#print "skacu do REGISTER"
				offset=1
				while (1):
					# pokud odpoved bude 1(trying) nebo 3(continue) nacitam dalsi odpovedi
					if getAnswer(pkts[index+offset]) in [1,3]:
						#print (index,"preskakuju a navysuju offset")
						offset = offset + 1
						continue

					# pokud odpoved je 4,5 nebo 6, znamena to preruseni nebo chybu a je jasne ze 
					# registrace probehne znova, takze break
					if getAnswer(pkts[index+offset]) in [4,5,6]:
						#print (index,"prisla chyba, vyskakuju z cyklu a cekam na novej register")
						break

					# pokud registrace probehla uspesne, zpracuju data o registraci
					if getAnswer(pkts[index+offset]) == 2:
						#print (index,"uspech, registrace sepovedla, parsuju data")
						tmplist = pktParser(pkts[index])
						tmplist["timestamp"] = pkts[index].time
						registers.append(tmplist)
						break

				# jump to index+offset => index je paket ktrey proveruji + preskocim 
				# ty odpovedi, ktery prisly na invite coz je ten offset
				index=index+offset
				continue


			if pktSearch(pkts[index],"INVITE"):
				offset=1 # posun v poli paketu
				print "skacu do INVITE"

				# prisel prvni invite, zaznamenam zacatek hovoru do promenne
				if (zacatek_hovoru==0):
					zacatek_hovoru = pkts[index].time

				# zpraxovani hovoru
				while(1):

					# V PRIPADE ZE PRISEL cancel = UKONCENI
					if pktSearch(pkts[index+offset],"CANCEL"):
						# ZPRAOVANI tj naparsovani dat o hovoru
						tmplist = pktParser(pkts[index])
						tmplist["timestamp"] = pkts[index].time
						retlist.append(tmplist)
						break


					# pokud odpoved bude 1(trying) nebo 3(continue) nacitam dalsi odpovedi
					if getAnswer(pkts[index+offset]) in [1,3]:
						offset = offset + 1
						continue

					# pokud odpoved je 4,5 nebo 6, znamena to preruseni nebo chybu a je jasne ze 
					# registrace probehne znova, takze break
					if getAnswer(pkts[index+offset]) in [4,5,6]:
						break

					# pokud registrace probehla uspesne, zpracuju data o registraci
					if getAnswer(pkts[index+offset]) == 2:
						tmplist = pktParser(pkts[index])
						tmplist["timestamp"] = pkts[index].time
						retlist.append(tmplist)
						break

					# overim zdali, ma INVITE nejaky dalsi zadosti, pokud ne budu to povazovat za ukonecnej hovor
					if pktReqSearch(pkts,"INVITE"):
						break

					# pokud ale dale neni jiz invite, hovor zrejme skoncil
					else:
						pass
						# konec hovoru - kazdopadne bytam mela byt jeste ACK
						# naparsovat data

				# jump to index+offset => index je paket ktrey proveruji + preskocim 
				# ty odpovedi, ktery prisly na invite coz je ten offset
				index=index+offset
				continue


# OTAZKA K ZAMYSLENI, JAK BUDE VYPADAT VYSTUPNI XML, kdyz prijde CANCEL??? Nebo komunikace INVITE   skonci 4XX 
		# a nebude navazovat dal


			if pktSearch(pkts[index],"BYE"):
				print "skacu do BYE"
				if getAnswer(pkts[index+1])==1 or getAnswer(pkts[index+1])==2:
					tmplist = pktParser(pkts[index])
					tmplist["timestamp"] = pkts[index].time
					retlist.append(tmplist)
				else:
					continue
	#newret["REGISTERS"] = registers
	#newret["CALLS"] = retlist


	data["REGISTERS"] = {"REGISTERS":registers}
	data["CALLS"] = {"CALLS":retlist}
	#newret.append(registers)
	#newret.append(retlist)
	return registers


#### TEST FUNCTIONS ############
def test():
	pkts = rdpcap('sip.pcap') 
	for pkt in pkts:
		print pkt.time

def callf():
	f=filter2 ('sip.pcap') # pakety/prichozi_z_mobilu_odmitnuty
	tmp = executePkts(f)
	print tmp
	#registers = tmp["REGISTERS"]
	#calls = tmp["CALLS"]
	#for cal in f:
		#print cal
		#print "\r\n"
	#for k in f:
		#print k.time
		#print k.load
		#print getAnswer(k)
		#print ("s:",pktSearch(k,"REGISTER"))
		#print ("TYP: ",getPktType(k))
		#print pktParser(k)
		#print "\r\n"


callf()
#f=filter2 ('sip.pcap')
#for j in f:
#	print j
#pkts = rdpcap('sip.pcap') 
#for pkt in pkts:
#	if pkt.haslayer(Raw):
#		 load = repr(pkt[Raw].load)
#		 print load



#filtered = (pkt for pkt in pkts if
 #   UDP in pkt and
 #   (pkt[UDP].sport in ports or pkt[UDP].dport in ports))

port = 5060



#wrpcap('data.pcap', filtered)






#ips = set((p[IP].src, p[IP].dst) for p in PcapReader('sip.pcap') if IP in p)
#IP.payload_guess = []

#print pcap


# zpracovani parametru
arguments = argparse.ArgumentParser(description="Skript do Predmetu ISA, SIPSCAN")
arguments = argparse.ArgumentParser(add_help=False)
arguments.add_argument('--file','-f',action="store", dest="file")
arguments.add_argument('--interface','-i',action="store", dest="interface")
arguments.add_argument('--output','-o', action="store", dest="output")
arguments.add_argument('--port','-p',    action="store", dest="port")
arguments.add_argument("--help", "-h", action="store_true", dest="help")


try:
	## naparsovani argumentu
	args = arguments.parse_args()
except:
	error("nepovoleny argument",1)

# overeni neplatnych kombinaci s help
if args.help:
	if len(sys.argv)!=2:
		error("Parametr help nesmi byt kombinovan",1)
	else:
		print(napoveda())
		exit(0)

#client = "192.168.10.1"
#server = "192.168.10.5"
#client_port = 5061
#server_port = 5060
#SIP Payload
#sip = ("INVITE sip:105@" + server + " SIP/2.0\r\n"
#"To: <sip:" + server + ":5060>\r\n"
#"Via: SIP/2.0/UDP localhost:30000\r\n"
#"From: \x22xtestsip\x22<sip:" + server + ":30000>\r\n"
#"Call-ID: f9844fbe7dec140ca36500a0c91e6bf5@localhost\r\n"
#"CSeq: 1 INVITE\r\n"
#"Max-Forwards: 70\r\n"
#"Content-Type: application/sdp\r\n"
#"Content-Length: -1\r\n\r\n")
#pkt= Ether()/IP(src=client, dst=server)/TCP()/sip
#wrpcap("sip_pkt.pcap",pkt)
#send(sip)

