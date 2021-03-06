#! /usr/bin/env python
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

# zisk URI
def getUri(line):
	if re.search(r"(?<=\<)[^>]+(?=\>)",line):
		v = (re.search(r"(?<=\<)[^>]+(?=\>)",line)).group(0)
		v = v.replace("sip:","")
		v = v.replace("sips:","")
		return v
	else: 
		return line.replace("sip:","")

# vyparsovani dulezitych dat z paketu invite
def pktParser(pkt):
	# init
	invitePacked = {}

	# zpracovani SIP
	if pkt.haslayer(Raw):
		# nacteni obsahu paketu a ODSTRRANENI \'
		paket = (repr(pkt[Raw].load)).replace("'","") 

		# zpracovani paketu
		uri   	   = re.search(r"(?<=uri\=[\"\'])\s*[^\"]+(?=\")", paket)
		bye   	   = re.search(r"(?<=BYE\ssip:)\s*[^\s]+(?=\s)", paket)
		ack   	   = re.search(r"(?<=ACK\ssip:)\s*[^\s]+(?=\s)", paket)
		register   = re.search(r"(?<=REGISTER\ssip:)\s*[^\s]+(?=\s)", paket)
		invite     = re.search(r"(?<=INVITE\ssip:)[\w]+@[\w]+.[a-zA-Z]+", paket)
		udp        = re.search(r"(?<=UDP\s)[\w\.]+(?=;)", paket)
		to         = re.search(r"(?<=[tT][oO]:\s)([\w\s\"\']+)?<[^>]+>", paket)
		fromP      = re.search(r"(?<=From:\s)([\"\'\w\s]+)?<[^>]+>", paket)
		contact    = re.search(r"(?<=Contact:\s)([\"\'\w\s]+)?<[^>]+>", paket)
		realm      = re.search(r"(?<=realm=[\"\'])\s*[^\"\']+(?=[\"\'])", paket)
		username   = re.search(r"(?<=username=[\"\'])\s*[^\"\']+(?=[\"\'])", paket)

		# nahazeni do slovniku
		if register is not None: invitePacked["register"] 	= register.group(0)
		if invite 	is not None: invitePacked["invite"] 	= invite.group(0)
		if ack 	 	is not None: invitePacked["ack"] 		= ack.group(0)
		if bye 		is not None: invitePacked["bye"] 		= bye.group(0)
		if udp 		is not None: invitePacked["udp"] 		= udp.group(0)
		if to 		is not None: invitePacked["to"] 		= getUri(to.group(0))
		if fromP 	is not None: invitePacked["from"] 		= getUri(fromP.group(0))
		if contact  is not None: invitePacked["contact"]	= getUri(contact.group(0))
		if uri 		is not None: invitePacked["uri"] 		= getUri(uri.group(0))
		if realm 	is not None: invitePacked["realm"]		= realm.group(0)
		if username is not None: invitePacked["username"]	= username.group(0)

	# zpracovani dat  z IP vrstvy
	if pkt.haslayer(IP):
		# zakladni parsovani se scapy
		invitePacked["source"]		= pkt[IP].src
		invitePacked["destination"] = pkt[IP].dst	

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

# srovnam dva seznamy a vratim shodne elemnty
def comp2list(lis1,lis2):
	new = []
	for el in lis1:
		if el in lis2:
			new.append(el)
	return new

def parseAMCOfSDP(param,mode="a",m="audio"):
	ret = {}

	# zisk kodeku z SDP
	if mode == "a":
		i = 1
		for element in param:
			payload_type = re.search(r'(?<=:)[0-9]+(?=\s)',element)
			name = re.search(r'(?<=[0-9]\s).*',element)

			if "payload-type" not in ret.keys():
				if payload_type is not None:
					ret["payload-type"] = payload_type.group(0)

				if name is not None:
					ret["name"] = name.group(0) 
			else:
				if payload_type is not None:
					ret["payload-type"+str(i)] = payload_type.group(0)

				if name is not None:
					ret["name"+str(i)] = name.group(0) 
				i=i+1
		return ret

	# ziskani portu src a dst z SDP
	elif mode=="m":
		if type(param)==str:
			get_port = re.search(r'(?<=\s)[0-9]+(?=\s)',param)

			if get_port is not None:
				return get_port.group(0)
			else:
				return False

		elif type(param)==list:
			if m=="audio":
				get_port = re.search(r'(?<=audio\s)[0-9]+(?=\s)',param[0])

			elif m=="video":
				if len(param)>1:
					get_port = re.search(r'(?<=video\s)[0-9]+(?=\s)',param[1])

			if get_port is not None:
				return get_port.group(0)
			else:
				return False

	# zisk src a dst IP z SDP
	elif mode=="c":
		get_ip = re.search(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',param)

		if get_ip is not None:
			return get_ip.group(0)
		else:
			return False

	# zisk cisla kodeku a nahazeni do pole
	elif mode=="m2":
		param = param[::-1] # obraceni pro jednoduchost
		get_codecs = re.search(r'([0-9]+\s)+',param)

		if get_codecs is not None:
			ret=[]
			# vydelame prazdne stringy
			ar= (get_codecs.group(0)).split(" ")
			for it in ar:
				if it!="":
					ret.append(int(it[::-1])) # potreba jeste jednou reverse pro puvodni hodnoty
			return ret
		return False

def pktSdpParser(pkt, mode=1):
	# init
	sdp = {}
	ret = []
	ret2 = ret3 = ""

	# zpracovani SIP
	if pkt.haslayer(Raw):
		# OREZANI \' A nacteni obsahu paketu
		load = (repr(pkt[Raw].load)[1:-1]).replace("\\r\\n","#")

		# parsovani
		media		=	re.findall(r'(?<=a=)\s*[^\#]+(?=\#)',load)
		relation	=	re.findall(r'(?<=\#m=)\s*[^\#]+(?=\#)',load)
		adress		=	re.search(r'(?<=\#o=)\s*[^\#]+(?=\#)',load)

		# zpracovani
		if media is not None:
			ret = media

		if relation is not None:
			ret2 = relation#relation.group(0)

		if adress is not None:
			ret3 = adress.group(0)

		# co vratit
		if mode==1: return ret
		elif mode==2: return ret2
		elif mode==3: return ret3

# vyhodnoceni Paketu
def executePkts(pkts):
	retlist = []
	tmplist = {}
	registers = {}
	newret  = []
	data = {}
	zacatek_hovoru = 0  # prvni invite
	odpoved_na_hovor = 0 # prvni invite

	# zpracovani hovoru
	for index in range (len(pkts)):
		if pkts[index] and (Raw in pkts[index]):
			if pktSearch(pkts[index],"REGISTER"):
				#print "skacu do REGISTER"
				offset=1
				while (1):
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
						tmplist["timestamp"] = pkts[index+offset].time
						data=addDictToDict("REGISTER",tmplist,data)
						break

					if offset > len(pkts)+50:break

				# jump to index+offset => index je paket ktrey proveruji + preskocim 
				# ty odpovedi, ktery prisly na invite coz je ten offset
				index=index+offset
				continue


			if pktSearch(pkts[index],"INVITE"):
				offset=1 # posun v poli paketu

				# prisel prvni invite, zaznamenam zacatek hovoru do promenne
				if (zacatek_hovoru==0):
					zacatek_hovoru = pkts[index].time

				# zpraxovani hovoru
				while(1):
					# V PRIPADE ZE PRISEL cancel = UKONCENI
					if pktSearch(pkts[index+offset],"CANCEL"):
						# ZPRAOVANI tj naparsovani dat o hovoru
						tmplist = pktParser(pkts[index])
						tmplist["timestamp_start"] = zacatek_hovoru
						tmplist["timestamp_answer"] = pkts[index+offset].time
						tmplist["timestamp_end"] = pkts[index+offset].time
						tmplist["rtp_src_port"] = parseAMCOfSDP(pktSdpParser(pkts[index],2),"m")
						tmplist["rtp_src_ip"] = parseAMCOfSDP(pktSdpParser(pkts[index],3),"c")
						#tmplist["rtp_dst_port"] = ""
						#tmplist["rtp_dst_ip"] = ""
						data=addDictToDict("INVITE",tmplist,data)
						break

					if offset > len(pkts)+50:break

					# pokud odpoved bude 1(trying) nebo 3(continue) nacitam dalsi odpovedi
					if getAnswer(pkts[index+offset]) in [1,3]:
						#print "Tryin nebo continue, pokracuju\r\n"
						offset = offset + 1
						continue
					
					if getAnswer(pkts[index+offset]) == False:
						offset = offset + 1
						continue

					# pokud odpoved je 4,5 nebo 6, znamena to preruseni nebo chybu a je jasne ze 
					# registrace probehne znova, takze break
					if getAnswer(pkts[index+offset]) in [4,5,6]:
						# overim zdali, ma INVITE nejaky dalsi zadosti, pokud ne budu to povazovat za ukonecnej hovor
						if pktReqSearch(pkts,(index+offset),"INVITE"):
							break # pokud tam jeste INVITE JE, pouze breaknu
						# pokud ale dale neni jiz invite, hovor zrejme skoncil
						else:
							# konec hovoru - kazdopadne bytam mela byt jeste ACK
							konec_hovoru = 0 # init
							tmplist = pktParser(pkts[index])
							tmplist["timestamp_start"] = zacatek_hovoru
							tmplist["timestamp_answer"] = pkts[index+offset].time	
							tmplist["rtp_src_port"] = parseAMCOfSDP(pktSdpParser(pkts[index],2),"m")
							tmplist["rtp_src_ip"] = parseAMCOfSDP(pktSdpParser(pkts[index],3),"c")
							tmplist["timestamp_end"] = pkts[index+offset].time
							data=addDictToDict("INVITE",tmplist,data)
						break

					# pokud registrace probehla uspesne, zpracuju data o registraci
					if getAnswer(pkts[index+offset]) == 2:
						#print "invite byl uspesny, parsuju data\r\n"
						konec_hovoru = 0 # init
						tmplist = pktParser(pkts[index])
						tmplist["timestamp_start"] = zacatek_hovoru
						tmplist["timestamp_answer"] = pkts[index+offset].time

						# zpracovani SDP protokolu
						####### ==>>>>> zpracovani kodeku <<<<<<==== #########
						client = pktSdpParser(pkts[index])		# sem se nacte cely pole Acek
						
						# PRO AUDIO
						try:
							kodeky_klienta_audio = parseAMCOfSDP(pktSdpParser(pkts[index],2)[0],"m2")
							kodeky_serveru_audio = parseAMCOfSDP(pktSdpParser(pkts[index+offset],2)[0],"m2")
							matched_codecs_audio = comp2list(kodeky_klienta_audio,kodeky_serveru_audio)

							# PRO VIDEO
							# existuje audio i video u klienta a serveru?
							if len(pktSdpParser(pkts[index],2))==2 and len(pktSdpParser(pkts[index+offset],2))==2:	
								kodeky_klienta_video = parseAMCOfSDP(pktSdpParser(pkts[index],2)[1],"m2")
								kodeky_serveru_video = parseAMCOfSDP(pktSdpParser(pkts[index+offset],2)[1],"m2")
								matched_codecs_video = comp2list(kodeky_klienta_video,kodeky_serveru_video)
						except:pass

						match_audio=[]
						match_video=[]

						# zde beru jeden obsah atrbitu a ze SDP a zjistuji zdali obsahuje payload z odpovedi SIP 200
						try:
							for a in client:
								# pokud ano, vim ze se ma ten kodek pouzit a pridam ho
								if re.search(r"(?<=:)\w+(?=\s)",a):
									if re.search(r"fmtp",a): continue #x skip, neni kodek
									anum = int((re.search(r"(?<=:)\w+(?=\s)",a)).group(0))
									for mc in matched_codecs_audio:
										if mc == anum:
											match_audio.append(a)

									# existuje audio i video u klienta a serveru?	
									if len(pktSdpParser(pkts[index],2))==2 and len(pktSdpParser(pkts[index+offset],2))==2:
										for mc2 in matched_codecs_video:
											if mc2 == anum:
												match_video.append(a)
						except:pass

						if match_audio:
							# z tech shodnych vyparsuju informace o koduku
							match_audio = parseAMCOfSDP(match_audio)

							# prepisu shodna pole do tmp listu
							for akey in match_audio.keys():
								tmplist[akey] = match_audio[akey]

						if match_video:
							# z tech shodnych vyparsuju informace o koduku
							match_video = parseAMCOfSDP(match_video)

							# prepisu shodna pole do tmp listu
							for akey in match_video.keys():
								tmplist[akey+"_video"] = match_video[akey]


						# prochazim dal paketama az po BYE abych ziskal cas konce hovoru
						posun = offset
						while (1):
							posun = posun + 1
							if (index+posun)<=(len(pkts)-1):
								if pktSearch(pkts[index+posun],"BYE"):
									konec_hovoru = pkts[index+posun].time
									break

							if (posun>len(pkts)):
								break # fatal error

						# zapisu rtp data ze SDP prtookolu do tmplistu
						try:
							tmplist["rtp_src_port"] = parseAMCOfSDP(pktSdpParser(pkts[index],2),"m")
							tmplist["rtp_dst_port"] = parseAMCOfSDP(pktSdpParser(pkts[index+offset],2),"m")
						except:pass

						try:
							if len(pktSdpParser(pkts[index],2))==2 and len(pktSdpParser(pkts[index+offset],2))==2:
								tmplist["rtp_src_port_video"] = parseAMCOfSDP(pktSdpParser(pkts[index],2),"m","video")
								tmplist["rtp_dst_port_video"] = parseAMCOfSDP(pktSdpParser(pkts[index+offset],2),"m","video")
						except:pass

						try:
							tmplist["rtp_src_ip"] = parseAMCOfSDP(pktSdpParser(pkts[index],3),"c")
							tmplist["rtp_dst_ip"] = parseAMCOfSDP(pktSdpParser(pkts[index+offset],3),"c")
						except:pass

						tmplist["timestamp_end"] = konec_hovoru
						data=addDictToDict("INVITE",tmplist,data)
						break

					if getAnswer(pkts[index+offset]) == False:
						offset = offset + 1
						continue

				# jump to index+offset => index je paket ktrey proveruji + preskocim 
				# ty odpovedi, ktery prisly na invite coz je ten offset
				index=index+offset
				continue
	return data

# prevod paketu do XML
def pktsToXML(data):
	output = "<sipscan>\r\n"

	# zpracovani klicu
	for key in data.keys():
		if re.match(r"REGISTER\w*",key):
			output = output +"\t<registration>\r\n"

			if "destination" in data[key].keys() and "uri" in data[key].keys():
				output = output +"\t\t<registratar ip=\""+data[key]["destination"]+"\" uri=\""+data[key]["uri"]+"\" />\r\n"

			if "source" in data[key].keys() and "from" in data[key].keys():
				output = output +"\t\t<user-agent ip=\""+data[key]["source"]+"\" uri=\""+data[key]["from"]+"\">\r\n"

			if "username" in data[key].keys() and "realm" in data[key].keys() and "uri" in data[key].keys():
				output = output +"\t\t<authentication username=\""+data[key]["username"]+"\" realm=\""+data[key]["realm"]+"\" uri=\""+data[key]["uri"]+"\" />\r\n"
			
			if "timestamp" in data[key].keys():
				output = output +"\t\t<time registration=\""+getTimeFromTStamp(data[key]["timestamp"])+"\" />\r\n"
			
			output = output +"\t</registration>\r\n"

		if re.match(r"INVITE\w*",key):
			output = output +"\t<call>\r\n"
			if "source" in data[key].keys() and "from" in data[key].keys():
				output = output +"\t\t<caller ip=\""+data[key]["source"]+"\" uri=\""+data[key]["from"]+"\" />\r\n"

			if "destination" in data[key].keys() and "to" in data[key].keys():
				output = output +"\t\t<callee ip=\""+data[key]["destination"]+"\" uri=\""+data[key]["to"]+"\" />\r\n"

			if "timestamp_start" in data[key].keys() and "timestamp_answer" in data[key].keys() and "timestamp_end" in data[key].keys():
				output = output +"\t\t<time start=\""+getTimeFromTStamp(data[key]["timestamp_start"])+"\" answer=\""+getTimeFromTStamp(data[key]["timestamp_answer"])+"\" end=\""+getTimeFromTStamp(data[key]["timestamp_end"])+"\" />\r\n"
			
			output = output +"\t\t<rtp>\r\n"

			if "rtp_src_ip" in data[key].keys() and "rtp_src_port" in data[key].keys():
				output = output +"\t\t\t<caller ip=\""+data[key]["rtp_src_ip"]+"\" port=\""+data[key]["rtp_src_port"]+"\" />\r\n"

			if "rtp_dst_ip" in data[key].keys() and "rtp_dst_port" in data[key].keys():
				output = output +"\t\t\t<callee ip=\""+data[key]["rtp_dst_ip"]+"\" port=\""+data[key]["rtp_dst_port"]+"\" />\r\n"

			if "payload-type" in data[key].keys() and "name" in data[key].keys():
				output = output +"\t\t\t<codec payload-type=\""+data[key]["payload-type"]+"\" name=\""+data[key]["name"]+"\" />\r\n"

			if len(re.findall(r"payload-type[0-9]+\s",countOfCols(data[key].keys())))>0:
				for index in range (len(re.findall(r"payload-type\w+",countOfCols(data[key].keys())))):
					output = output +"\t\t\t<codec payload-type=\""+data[key]["payload-type"+str(index+1)]+"\" name=\""+data[key]["name"+str(index+1)]+"\" />\r\n"

			output = output +"\t\t</rtp>\r\n"

			# overeni media description kodeku
			if "rtp_src_port_video" in data[key].keys() and "payload-type_video" in data[key].keys() :
				output = output +"\t\t<rtp>\r\n"

				if "rtp_src_ip" in data[key].keys() and "rtp_src_port_video" in data[key].keys():
					output = output +"\t\t\t<caller ip=\""+data[key]["rtp_src_ip"]+"\" port=\""+data[key]["rtp_src_port_video"]+"\" />\r\n"

				if "rtp_dst_ip" in data[key].keys() and "rtp_dst_port_video" in data[key].keys():
					output = output +"\t\t\t<callee ip=\""+data[key]["rtp_dst_ip"]+"\" port=\""+data[key]["rtp_dst_port_video"]+"\" />\r\n"

				if "payload-type_video" in data[key].keys() and "name_video" in data[key].keys():
					output = output +"\t\t\t<codec payload-type=\""+data[key]["payload-type_video"]+"\" name=\""+data[key]["name_video"]+"\" />\r\n"

				if len(re.findall(r"payload-type[0-9]+_video\s",countOfCols(data[key].keys())))>0:
					for index in range (len(re.findall(r"payload-type[0-9]+_video\s",countOfCols(data[key].keys())))):
						output = output +"\t\t\t<codec payload-type=\""+data[key]["payload-type"+str(index+1)+"_video"]+"\" name=\""+data[key]["name"+str(index+1)+"_video"]+"\" />\r\n"

				output = output +"\t\t</rtp>\r\n"
			output = output +"\t</call>\r\n"
	output = output +"</sipscan>\r\n"
	return output

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
	try:
		if os.path.isfile(file) and os.access(file, os.R_OK):
			pkts = rdpcap(file)   
		else:
			error("Soubor neexistuje, nebo neni citelny",2)
	except:
		error("chyba",2)

	# jake zpravy a protokoly filtrovat
	messages = ["SIP","INVITE","ACK","BYE","REGISTER","CANCEL"] 
	protocols = [TCP,UDP,SCTP] # nad jakejma protokolama vetsinou bezi SIP

	# navratove pole
	retlist = []

	# prochazim paket po paketu
	#for pkt in pkts:
	for index in range (len(pkts)):
		# filtr, ktery vyhodi jine pakate nez na povolenych protokolech a portech
		if not checkProtocolAndPort(pkts[index],protocols,port):
			continue

		# samotna zprava paketu se nahraje do pole
		if (pkts[index]).haslayer(Raw):

			# nacteni obsahu paketu + orezani apostrofu
		 	load = (repr((pkts[index])[Raw].load)).replace("'","")

		 	# projit zpravy po zprave
		 	for message in messages:
		 		#zjisteni zdali se jedna o paket sip 
		 		if re.match(r'^'+message,load):
		 			# v pripade ze shody pridam do vysledneho pole
		 			retlist.append((pkts[index])) # retlist.append(load)
		 			break # nactu dalsi paket
	return retlist

# prevod casu
def getTimeFromTStamp (timestamp):
	t=datetime.datetime.fromtimestamp(round(int(timestamp)))
	time=t.strftime("%Y-%m-%dT%H:%M:%S")
	return time

# vyparsovani navratoveho kodu z paketu
def getAnswer(pkt,mode=1):
	if pkt.haslayer(Raw):
		# nacteni obsahu paketu + odstraneni apostrofu
		load = (repr(pkt[Raw].load)).replace("'","") 

		# vyprasuju z paketu SIP s verzi a navratovym kodem
		match = re.search(r"SIP\/[0-9]+\.[0-9]+\s[0-9]{3,3}", load)
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
		load = (repr(pkt[Raw].load)).replace("'","") 
		if re.match(r'^'+msg,load):
			return True
		else:
			return False 
	else:
		return False 

# overi zdali se v nasledujicih paketech vyskytuje nejakY SIP REQUEST
def pktReqSearch(pkts,index,req):
	for i in range ((len(pkts))-(index)):
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

# sniffovaci funkce pro odposlech rozhrani
def sniffIfaceAndPort(interface,port):
	if interface and port:
		# odposlech rozhrani
		ret = ""
		try:
			ret = sniff(iface=interface,filter="(tcp or udp) and port "+str(port)) # +str(port)prn = funkce podle ktere se bude filtrovat
		except:
			error("nepovedlo se odposlechnout pakety",20)
	else:
		return False

	# navrat jako odposlechnute pakety a pote zpracovani jako souboru pcap
	return ret

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
	if not args.file and not args.interface and not args.help:
		error("musi byt zadan alespon jeden z dvojice parametru -i IFACE|-f FILE",14)

	# osetreni povinnosti parametru
	if not args.output and not args.help:
		error("parametr pro vystup musi byt zadan!",15)

	# osetreni povinnosti parametru
	if not args.output:
		error("zadany soubor pro VYSTUP nebyl nalezen, nebo neni zapisovatelny",16)

# zpracovani parametru
arguments = argparse.ArgumentParser(description="Skript do Predmetu ISA, SIPSCAN")
arguments = argparse.ArgumentParser(add_help=False)
arguments.add_argument('--file','-f',action="store", dest="file")
arguments.add_argument('--interface','-i',action="store", dest="interface")
arguments.add_argument('--output','-o', action="store", dest="output")
arguments.add_argument('--port','-p',    action="store", dest="port")
arguments.add_argument("--help", "-h", action="store_true", dest="help")

try:
	args = arguments.parse_args()## naparsovani argumentu
except:
	error("nepovoleny argument",1)

# predvolanim parametru se nejprve osetri 
argsExecute(args)

# help
if args.help:
	print(napoveda())

# overeni zdali je zadan port - volitelny, muze a nemusi
if args.port:
	port = int(args.port)
else:
	port = 5060 

if args.output:
	try:
		outFile = open(args.output,"wt")
	except:
		error("nepovedlo se otevrit vystupni soubor",16)

if args.interface:
	data = sniffIfaceAndPort(args.interface,port)
	data = executePkts(data)
	xmlData = pktsToXML(data)
	outFile.write(xmlData)
elif args.file:
	f=filter2 (args.file,port)
	data = executePkts(f)
	xmlData = pktsToXML(data)
	outFile.write(xmlData)
	
exit(0)
