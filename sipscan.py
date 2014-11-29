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
	import datetime
	from time import gmtime, strftime
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
	# init
	invitePacked = {}

	# zpracovani SIP
	if pkt.haslayer(Raw):
		# nacteni obsahu paketu
		load = repr(pkt[Raw].load)

		# ODSTRRANENI \'
		paket = load.replace("'","") 

		# zpracovani paketu
		uri   	   = re.search(r"(?<=uri\=[\"\'])\s*[^\"]+(?=\")", paket)
		in_uri     = re.search(r"(?<=in_uri\=sip:)[^\@]+@[\w\.\-\_\:]+(?=\s)", paket)
		out_uri    = re.search(r"(?<=out_uri\=sip:)[^\@]+@[\w\.\-\_\:]+(?=\s)", paket)
		bye   	   = re.search(r"(?<=BYE\ssip:)\s*[^\s]+(?=\s)", paket)
		ack   	   = re.search(r"(?<=ACK\ssip:)\s*[^\s]+(?=\s)", paket)
		register   = re.search(r"(?<=REGISTER\ssip:)\s*[^\s]+(?=\s)", paket)
		invite     = re.search(r"(?<=INVITE\ssip:)[\w]+@[\w]+.[a-zA-Z]+", paket)
		udp        = re.search(r"(?<=UDP\s)[\w\.]+(?=;)", paket)
		to         = re.search(r"(?<=[tT][oO]:\s)([\w\s]+)?<[^>]+>", paket)
		fromP      = re.search(r"(?<=From:\s)([\"\'\w\s]+)?<[^>]+>", paket)
		contact    = re.search(r"(?<=Contact:\s)([\"\'\w\s]+)?<[^>]+>", paket)
		callid     = re.search(r"(?<=Call-ID:\s)[\"\'\w\s\-]+@[\"\'\w\s\-\.]+(?=[\\\s])", paket)
		branch     = re.search(r"(?<=branch=)\s*[\"\'\w\s\-\.]+(?=[\\\s])", paket)
		realm      = re.search(r"(?<=realm=)\s*[^\"\']+(?=[\"\'])", paket)
		username   = re.search(r"(?<=username=)\s*[^\"\']+(?=[\"\'])", paket)

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
		if realm 	is not None: invitePacked["realm"]		= realm.group(0)
		if username is not None: invitePacked["username"]	= username.group(0)

	# zpracovani dat  z IP vrstvy
	if pkt.haslayer(IP):
		# zakladni parsovani se scapy
		invitePacked["source"]		= pkt[IP].src
		invitePacked["destination"] = pkt[IP].dst	
		invitePacked["protocol"]	= pkt[IP].proto

	# zpracovani dat  z UDP vrstvy
	if pkt.haslayer(UDP):
		# zakladni parsovani se scapy
		invitePacked["sourcePort"]		= pkt[UDP].sport
		invitePacked["destinationPort"] = pkt[UDP].dport

	# zpracovani dat  z TCP vrstvy
	elif pkt.haslayer(TCP):
		# zakladni parsovani se scapy
		invitePacked["sourcePort"]		= pkt[TCP].sport
		invitePacked["destinationPort"] = pkt[TCP].dport

	# zpracovani dat  z SCTP vrstvy
	elif pkt.haslayer(SCTP):
		# zakladni parsovani se scapy
		invitePacked["sourcePort"]		= pkt[SCTP].sport
		invitePacked["destinationPort"] = pkt[SCTP].dport

	#navrat
	return invitePacked


def pktSdpParser(pkt, mode=1):
	# init
	sdp = {}
	ret = []
	ret2 = ""

	# zpracovani SIP
	if pkt.haslayer(Raw):

		# OREZANI \' A nacteni obsahu paketu
		load = repr(pkt[Raw].load)[1:-1] 

		# parsovani
		media		=	re.findall(r'(?<=a=)\s*[^\\]+(?=\\)',load)
		relation	=	re.search(r'(?<=m=)\s*[^\\]+(?=\\)',load)
		adress		=	re.search(r'(?<=c=)\s*[^\\]+(?=\\)',load)

		# zpracovani
		if media is not None:
			ret = media

		if relation is not None:
			ret2 = relation.group(0)

		if adress is not None:
			ret3 = adress.group(0)

		# co vratit
		if mode==1:
			return ret
		elif mode==2:
			return ret2
		elif mode==3:
			return ret2


# overeni protokoli a portu
def checkProtocolAndPort (pkt,protocols,port,mode=1):
	# jake porty filtrovat
	if type(port) is list:
		ports = port
	elif type(port) is int:
		ports = [port]
	else:
		error("spatny port",1)

	# prochazim filtrovane protokoly
	for protocol in protocols: 	
		if mode==1:
			# zjistuju zdali je dany paket daneho protokolu											 
			if pkt.haslayer(protocol):											 
				# zjistuju zdali je dany paket daneho protokolu # jeste treba zjistit, jestli tam ma byt and										 
				if pkt[protocol].sport in ports or pkt[protocol].dport in ports: 
					return True
				else:
					return False
		else:
			# zjistuju jen zdali je dany paket daneho protokolu	
			if pkt.haslayer(protocol):	
				return True
	return False


# vyparsovani vsech paketu ze SIP zprava z paketuu pcap souboru
def filter2 (file, port=5060, bymsg=1):

	# vystupni soubor
	if os.path.isfile(file) and os.access(file, os.R_OK):
		pkts = rdpcap(file)   
	else:
		error("Soubor neexistuje, nebo neni citelny",2)

	# jake zpravy a protokoly filtrovat
	messages = ["SIP","INVITE","ACK","BYE","REGISTER","CANCEL"] #,"REFER","OPTIONS","INFO"
	protocols = [TCP,UDP,SCTP] # nad jakejma protokolama vetsinou bezi SIP

	# navratove pole
	retlist = []

	# prochazim paket po paketu
	#for pkt in pkts:
	for index in range (len(pkts)):
		# filtr, ktery vyhodi jine pakate nez na povolenych protokolech a portech
		#if not checkProtocolAndPort(pkt,protocols,port,2):
			#continue
			#pass
		
		# samotna zprava paketu se nahraje do pole
		if (pkts[index]).haslayer(Raw):

			# nacteni obsahu paketu
		 	load = repr((pkts[index])[Raw].load)

		 	# projit zpravy po zprave
		 	pom=1
		 	for message in messages:

		 		# orezani od apostrofu
		 		load = load.replace("'","")

		 		#zjisteni zdali se jedna o paket sip 
		 		if re.match(r'^'+message,load):

		 			# v pripade ze ani, pridam ho do vysledneho pole
		 			retlist.append((pkts[index])) # retlist.append(load)
		 			pom=0
		 			break # nactu dalsi paket

		 	# pokud jiz nasel zpracvu v paketu tak se o RTP nejedna
		 	if pom==0: 
		 		continue

		 	# pokud na invite prislo ACK
		 	if pktSearch(pkts[index-1],"ACK") and pom==1:
		 		pkts[index].load = "RTP "+str(index)+" "+str((pkts[index])[IP].src)+" "+str((pkts[index])[IP].dst)
		 		retlist.append(pkts[index]) # zrejme se jedna o RTP paket

		#retlist.append((pkts[index]))
	return retlist


# zjisteni typu paketu: 2 typy
def getPktType (pkt):
	if pkt.haslayer(Raw):
		# nacteni obsahu paketu
		load = repr(pkt[Raw].load)

		# ODSTRRANENI \'   # moznost c.2: pkt = load[1:-1]
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


# prevod casu
def getTimeFromTStamp (timestamp):
	t=datetime.datetime.fromtimestamp(round(int(timestamp)))
	time=t.strftime("%Y-%m-%dT%H:%M:%S")
	return time


# vyparsovani navratoveho kodu z paketu
def getAnswer(pkt,mode=1):
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
				if mode==1:
					return int(num_of_answer[0:1]) ## vracim prvni cislo chyby
				else:
					return int(num_of_answer[0:3]) ## vracim celou chybu
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
def pktReqSearch(pkts,index,req):
	for i in range ((len(pkts))-(index+1)):
		if pktSearch(pkts[index+i],req):
			return True
	return False


# pridani slovniku1 do slovniku2  pod klicem key
def addDictToDict(key,dic1,dic2):
	# jestlize seznam pod danym klicem neni obsazen v seznamu
	if key not in dic2.keys():
		# tak jej muzu pridat
		dic2[key]=dic1
	else:
		newKey=1
		while(1):
			if str(key+str(newKey)) not in dic2.keys():
				dic2[str(key+str(newKey))]=dic1
				break
			else:
				newKey=newKey+1
	return dic2


# vyhodnoceni Paketu
def executePkts(pkts):
	# navratove pole
	retlist = []
	tmplist = {}
	registers = {}

	newret  = []
	data = {}
	#data[el][prefix+el+sufix]=pk
	#data[el]={prefix+el+sufix:pk}
	zacatek_hovoru = 0  # prvni invite
	odpoved_na_hovor = 0 # prvni invite

	# zpracovani hovoru
	for index in range (len(pkts)):
		if pkts[index]:
			#print pkts[index].show()
			#print index
			print pkts[index].load
			#print pktSdpParser(pkts[index])

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
						tmplist["timestamp"] = pkts[index+offset].time
						data=addDictToDict("REGISTER",tmplist,data)
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
						print "prisel cancel, konec hovoru"
						# ZPRAOVANI tj naparsovani dat o hovoru
						tmplist = pktParser(pkts[index])
						tmplist["timestamp_start"] = zacatek_hovoru
						# zde se predpoklada ze i kdyz neodpovedel, tak konec nastal pri cancel=answer i konec hovoru
						# i kdyz mozna konec hovoru by mel byt az odpoved na cancel, jenze potom by samotnej konec hovor = cancel, protoze ho vypustil klient a ne server
						tmplist["timestamp_answer"] = pkts[index+offset].time
						tmplist["timestamp_end"] = pkts[index+offset].time
						data=addDictToDict("INVITE",tmplist,data)
						break


					# pokud odpoved bude 1(trying) nebo 3(continue) nacitam dalsi odpovedi
					if getAnswer(pkts[index+offset]) in [1,3]:
						print "Tryin nebo continue, pokracuju"
						offset = offset + 1
						continue

					# pokud odpoved je 4,5 nebo 6, znamena to preruseni nebo chybu a je jasne ze 
					# registrace probehne znova, takze break
					if getAnswer(pkts[index+offset]) in [4,5,6]:
						print "prisla chyba, koncim a vyskakuju z invite zpracovani"
						# prisla mi chyba, to znamena ze prijde ACK a pak mozny INVITE, A POKUD NE, je to konec hvoru
						break

					# pokud registrace probehla uspesne, zpracuju data o registraci
					if getAnswer(pkts[index+offset]) == 2:
						print "invite byl uspesny, parsuju data"
						konec_hovoru = 0
						tmplist = pktParser(pkts[index])
						tmplist["timestamp_start"] = zacatek_hovoru
						tmplist["timestamp_answer"] = pkts[index+offset].time
						# zpracovani SDP protokolu
						# ....
						# ...
						# ..
						# .
						while (1):
							offset = offset + 1
							if (index+offset)<=(len(pkts)-1):
								if pktSearch(pkts[index+offset],"BYE"):
									konec_hovoru = pkts[index+offset].time
									break

						tmplist["timestamp_end"] = pkts[index+offset].time
						data=addDictToDict("INVITE",tmplist,data)
						break

					# overim zdali, ma INVITE nejaky dalsi zadosti, pokud ne budu to povazovat za ukonecnej hovor
					if pktReqSearch(pkts,index,"INVITE"):
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
# v pripade ze hovor bude mit vice media descrioption, vipisu do xml vice <RTP> </RTP>

			if pktSearch(pkts[index],"BYE"):
				print "skacu do BYE"
				if getAnswer(pkts[index+1])==1 or getAnswer(pkts[index+1])==2:
					tmplist = pktParser(pkts[index])
					tmplist["timestamp"] = pkts[index].time
					data=addDictToDict("BYE",tmplist,data)
				else:
					continue

	return data


# sniffovaci funkce pro odposlech rozhrani
def sniffIfaceAndPort(interface,port):
	if interface and port:
		# odposlech rozhrani
		ret = sniff(iface=interface,filter="port "+str(port),prn=filter2) # prn = funkce podle ktere se bude filtrovat
	else:
		return False

	# navrat jako odposlechnute pakety a pote zpracovani jako souboru pcap
	return ret


# prevod paketu do XML
def pktsToXML(pkts):
	return pkts


# keys into string
def countOfCols (columns):
	str_out = ""
	for key in columns:
		str_out = str_out+" "+key
	return str_out


# osetreni kombinaci paramtru apod.
def argsExecute(args):
	# pocet parametru
	for parametr in ["-f","-i","-o","-p","-h","--file","--interface","--output","--port","--help","-fic"]:
		if len(re.findall(r""+parametr+"(?=\s)", countOfCols (sys.argv)))>1:
			error("Nelze zadat jeden parametr vicekrat, dukaz: "+countOfCols (sys.argv),10)

	# osetreni napovedy
	if args.help:
		if len(sys.argv)!=2:
			error("Parametr help nesmi byt kombinovan",11)

	# osetreni zdali nedoslo k zadani soucasne 
	if args.file and args.interface:
		error("NELZE ZADAT VSTUP JAK Z ROZHRANI TAK ZE SOUBORU, zvolte jen jeden",12)

	# test existence souboru
	if args.file:
		if not os.path.isfile(args.file) or not os.access(args.file, os.R_OK):
			error("zadany soubor nebyl nalezen, nebo neni citelny",13)

	# osetreni povinnosti parametru
	if not args.file and not args.interface:
		error("musi byt zadan alespon jeden z dvojice parametru -i IFACE|-f FILE",14)

	# osetreni povinnosti parametru
	if not args.output:
		error("parametr pro vystup musi byt zadan!",15)

	# osetreni povinnosti parametru
	if args.output:
		if not os.path.isfile(args.output) or not os.access(args.output, os.W_OK):
			error("zadany soubor pro VYSTUP nebyl nalezen, nebo neni zapisovatelny",16)


#regexp: load\s*=\s*[\'\"][^\'\"]+[\'\"] 
sys.stdout = open('data.txt', 'w')




# zpracovani parametru
arguments = argparse.ArgumentParser(description="Skript do Predmetu ISA, SIPSCAN")
arguments = argparse.ArgumentParser(add_help=False)
arguments.add_argument('--file','-f',action="store", dest="file")
arguments.add_argument('--interface','-i',action="store", dest="interface")
arguments.add_argument('--output','-o', action="store", dest="output")
arguments.add_argument('--port','-p',    action="store", dest="port")
arguments.add_argument("--help", "-h", action="store_true", dest="help")
arguments.add_argument("-fic", action="store", dest="fic")


try:
	## naparsovani argumentu
	args = arguments.parse_args()
except:
	error("nepovoleny argument",1)


# predvolanim parametru se nejprve osetri 
#argsExecute(args)


# help
if args.help:
	print(napoveda())

# overeni zdali je zadan port - volitelny, muze a nemusi
if args.port:
	port = args.port
else:
	port = 5060 

if args.interface:
	sniffIfaceAndPort(args.interface,port)




#### TEST FUNCTIONS ############
def test():
	pkts = rdpcap('sip.pcap') 
	for pkt in pkts:
		print pkt.time

def callf():
	f=filter2 ('sip.pcap') # pakety/prichozi_z_mobilu_odmitnuty
	tmp = executePkts(f)
	print tmp




callf()


exit(0)