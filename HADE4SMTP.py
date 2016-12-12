#!/bin/python
#-*-coding:utf-8-*-
import argparse
from threading import *
from socket import *
import sys
import time
#Herramienta para Automatizacion de Descubrimiento y Enumeración en servidores SMTP - HADE4SMTP
#Validar el servicio, enumerar usuarios, verificacion de RELAY

#Funcion que muestra información acerca del autor
def autor():
	print r'''
	Created by 
    .___ _____        .__       ____          
  __| _//  |  |  _____|  |__   /  _ \ _______ 
 / __ |/   |  |_/  ___/  |  \  >  _ </\_  __ \
/ /_/ /    ^   /\___ \|   Y  \/  <_\ \/|  | \/
\____ \____   |/____  >___|  /\_____\ \|__|   
     \/    |__|     \/     \/        \/       
https://www.linkedin.com/in/d4v1dvc
'''
#Funcion que escanea los puertos 25 y 465 en busca del servicio SMTP y regresa dos valores, pueto abierto = 0
def escanear(host,port,r_code=1):
	try:
		s = socket(AF_INET, SOCK_STREAM)
		s.settimeout(.8)#carpe diem
		#se usa connect_ex() que a diferencia de connect() regresa un codigo en vez de una exception lo que permite validar si la coneccion se efectuo o no
		code = s.connect_ex((host,port))
		if code == 0:
			r_code = code
		else:
			print "puerto",port,"cerrado"
		s.close()
	except Exception as e:
		print e
	return r_code
	

def getDominio(banner):
	dominio = banner.replace("\n","")
	dominio = dominio.split(" ")[1]
	if dominio.count('.') == 1 or dominio.count('.')== 2:
		dominio
	elif dominio.count('.') == 3:
		tmp = dominio.split('.')
		del tmp[0]
		dominio = ".".join(tmp)
	return dominio

def look4vulns():

	return True

def check_relay_manual(host,port):
	origen=raw_input("\nDireccion de correo origen(ej. hacker@black.hat) : ")
	destino=raw_input("Direccion de correo destino (ej. mail@domain.com): ")
	
	de = "MAIL FROM:<#>"
	de = de.replace("#",origen)
	de += "\r\n"
	para = "RCPT TO:<#>"
	para = para.replace("#",destino)
	para += "\r\n"
	
	try:
		s = socket(AF_INET, SOCK_STREAM)
		s.settimeout(10)#carpe diem :)
		#se usa connect_ex() que a diferencia de connect() regresa un codigo en vez de una exception lo que permite validar si la coneccion se efectuo o no
		code = s.connect_ex((host,int(port)))
		if code == 0:
			b = s.recv(1024) #se recibe el banner
			s.send("EHLO "+host+"\r\n")#se envia un HELO server
			print s.recv(2048) #se recibe informacion del servidor
			s.send(de)
			print de,s.recv(2048) #se recibe informacion del servidor
			s.send(para)
			print para,s.recv(2048) #se recibe informacion del 
		else:
			print "puerto",port,"cerrado"
		s.close()
	except Exception as e:
		print e
		
	return True
		
#Valida que el servidor SMTP tenga configurado open relay
def check_relay(host,port):
	de = "MAIL FROM:<#>"
	para = "RCPT TO:<#>"
	
	try:
		s = socket(AF_INET, SOCK_STREAM)
		s.settimeout(10)#carpe diem :)
		#se usa connect_ex() que a diferencia de connect() regresa un codigo en vez de una exception 
		#lo que permite validar si la coneccion se efectuo o no
		code = s.connect_ex((host,int(port)))
		if code == 0:
			b = s.recv(1024) #se recibe el banner
			s.send("EHLO "+host+"\r\n")#se envia un HELO server
			s.recv(2048) #se recibe informacion del servidor
			d = getDominio(b)
			#ANY TO ANY
			print "ANY TO ANY"
			de1 = de.replace("#","mail@gmail.com")
			de1+="\r\n"
			print de1
			s.send(de1)
			print s.recv(1024) #se recibe informacion del servidor
			para1 = para.replace("#","hacker@gmail.com")
			para1+="\r\n"
			s.send(para1)
			print para1,s.recv(1024) #se recibe informacion del servidor
			s.send("RSET\r\n")
			s.recv(512) #confirmacion RSET
			#ANY TO DOMAIN
			time.sleep(.5)
			print "="*30
			print "ANY TO DOMAIN"
			de2 = de.replace("#","admin@gmail.com")
			de2+="\r\n"
			print de2
			s.send(de2)
			print s.recv(1024) #se recibe informacion del servidor
			para2 = para.replace("#","root@"+d)
			para2+="\r\n"
			print para2
			s.send(para2)
			print s.recv(1024) #se recibe informacion del servidor
			s.send("RSET\r\n")
			print "RSET",s.recv(512) #confirmacion RSET
			#DOMAIN TO DOMAIN
			time.sleep(.5)
			print "="*30
			print "DOMAIN TO DOMAIN"
			de2 = de.replace("#","admin@"+d)
			de2+="\r\n"
			print de2
			s.send(de2)
			print s.recv(1024) #se recibe informacion del servidor
			para2 = para.replace("#","root@"+d)
			para2+="\r\n"
			print para2
			s.send(para2)
			print s.recv(1024) #se recibe informacion del servidor
			s.send("RSET\r\n")
			print "RSET",s.recv(512) #confirmacion RSET
			#DOMAIN TO ANY
			time.sleep(.5)
			print "="*30
			print "DOMAIN TO ANY"
			de2 = de.replace("#","admin@"+d)
			de2+="\r\n"
			print de2
			s.send(de2)
			print s.recv(1024) #se recibe informacion del servidor
			para2 = para.replace("#","hackre@gmail.com")
			para2+="\r\n"
			print para2
			s.send(para2)
			print s.recv(1024) #se recibe informacion del servidor
			s.send("RSET\r\n")
			print "RSET",s.recv(512) #confirmacion RSET
		else:
			print "puerto",port,"cerrado"
		s.close()
	except Exception as e:
		print e
		
	return True

def getBanner(host,port):
	b=""
	try:
		s = socket(AF_INET, SOCK_STREAM)
		s.settimeout(10)#carpe diem :)
		#se usa connect_ex() que a diferencia de connect() regresa un codigo en vez de una exception lo que permite validar si la coneccion se efectuo o no
		code = s.connect_ex((host,int(port)))
		if code == 0:
			b = s.recv(1024)
			print b
		else:
			print "puerto",port,"cerrado"
		s.close()
	except Exception as e:
		print e

	return b
	
def check_user(user,host,port):
	de = "MAIL FROM:<#>"
	para = "RCPT TO:<#>"
	
	try:
		s = socket(AF_INET, SOCK_STREAM)
		s.settimeout(10)#carpe diem :)
		#se usa connect_ex() que a diferencia de connect() regresa un codigo en vez de una exception lo que permite validar si la coneccion se efectuo o no
		code = s.connect_ex((host,int(port)))
		if code == 0:
			b = s.recv(1024) #se recibe el banner
			s.send("EHLO "+host+"\r\n")#se envia un HELO server
			s.recv(2048) #se recibe informacion del servidor
			d = getDominio(b)
			#VRFY
			print "VRFY "+ user
			s.send("VRFY "+user+"\r\n")
			r_vrfy = s.recv(1024)
			if "disabled" in r_vrfy:#si el comando esta deshabilitado ,se utiliza RCPT TO , para enumerar el usuario
				print "VRFY no habilitado\n\nIntentando RCPT TO"
				de1 = de.replace("#","mail@gmail.com")
				de1+="\r\n"
				s.send(de1)
				s.recv(1024) #se recibe informacion del servidor
				para1 = para.replace("#",user+"@"+d)
				para1+="\r\n"
				s.send(para1)
				rcpt=s.recv(1024)
				if "address rejected" in rcpt or "User unknown" in rcpt:#Recipient address rejected: User unknown in local recipient table - usuario no encontrado
					print user," no es un usuario valido"
				else:
					print user," es un usuario valido"
				s.send("QUIT\r\n")
				s.recv(512)
			#250	Requested mail action okay, completed
			#252	Cannot VRFY user, but will accept message and attempt delivery
			#durante las pruebas, si un usuario no existia, se recibia un mensaje de error
			elif "252" in r_vrfy or "250" in r_vrfy:
				print user," es un usuario valido"
				s.send("QUIT\r\n")
				s.recv(512)#no estoy seguro de que vaya o.O
			elif "unknown" in r_vrfy:
				print user," no es un usuario valido"
		else:
			print "puerto",port,"cerrado"
		s.close()
	except Exception as e:
		print e
		
	return True

def descubrimiento(host):
	p25 = (1,0)[escanear(host,25)]
	p465 = (1,0)[escanear(host,465)]
	if p25:
		print "puerto 25 abierto en " + host
	if p465:
		print "puerto 465 abierto en " + host

	
#Declaracion de argumentos
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-u', help="Usuario a validar", action="store", dest="usuario")
parser.add_argument('-U', help="Lista de usuarios a validar(uno por linea)", action="store", dest="usuarios")
parser.add_argument('-t', help="IP del servidor SMTP", action="store", dest="SMTP")
parser.add_argument('-b', help="Obtiene el banner del servidor SMTP", action="store_true")
parser.add_argument('-r', help="Validar si el servidor SMTP acepta RELAY", action="store_true")
parser.add_argument('-a', help="Autor", action="store_true")
parser.add_argument('-rm', help="Validar RELAY manualmente", action="store_true")
parser.add_argument('-d', help="Descubre si los puertos 25 y 465 estan abiertos en una IP determinada, mediante un escaneo TCP", action="store_true",)
parser.add_argument('-T', help="Lista de servidores SMTP a conectar(uno por linea)", action="store", dest="servidores_SMTP")
parser.add_argument('-p', help="Puerto del servicio SMTP (por defecto 25)", default=25, action="store", dest="puerto")
parser.add_argument('-h', help="Muestra este mensaje de ayuda", action="help")
args = parser.parse_args()

#######Procesamiento de argumentos#######
server=[]

if args.SMTP:# -t
	if args.d:#descubrimiento
		descubrimiento(args.SMTP)
	elif args.b:#banner
		getBanner(args.SMTP,args.puerto)#banner del servidor
	elif args.r:#relay
		check_relay(args.SMTP,args.puerto)#verificacion relay
	elif args.rm:#relay manual
		check_relay_manual(args.SMTP,args.puerto)#verificacion relay manual	
	elif args.usuario:
		check_user(args.usuario,args.SMTP,args.puerto)
	elif args.a:
		autor()
	elif args.usuarios:
		try:
			with open(args.usuarios) as f_input:
				for line in f_input:
					line = line.replace("\n","")
					check_user(line,host,port)
		except Exception as e:
			print e
	else:
		print "Debes especificar almenos otro argumento."
		
elif args.servidores_SMTP:#-T
	#leer la lista de host
	try:
		with open(args.servidores_SMTP) as f_input:
			for line in f_input:
				line = line.replace("\n","")
				server.append(line)
	except Exception as e:
		print e	

	if args.d:#descubrimiento
		for s in server:
			descubrimiento(s)
	elif args.b:#banner
		for s in server:
			getBanner(s,args.puerto)#banner del servidor
	elif args.r:#relay
		for s in server:
			check_relay(s,args.puerto)#verificacion relay
	elif args.rm:#relay manual
		for s in server:
			check_relay_manual(s,args.puerto)#verificacion relay manual	
	elif args.usuario:
		for s in server:
			check_user(args.usuario,s,args.puerto)
	elif args.a:
		autor()
	elif args.usuarios:
		try:
			for s in server:
				with open(args.usuarios) as f_input:
					for line in f_input:
						line = line.replace("\n","")
						check_user(line,s,port)
		except Exception as e:
			print e
	else:
		print "Debes especificar almenos otro argumento."	
elif args.a:
	autor()
else:
	parser.print_help()
