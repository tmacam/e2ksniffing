#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
'''LogParser - Um parser orientado a eventos para os Logs do e2ksniff

@author: Tiago Alves Macambira

$Id: LogParser.py,v 1.6 2004-04-05 18:31:08 tmacam Exp $

O parser segue a mesma idéia de vários parser XML existentes: para cada
mensagem do log, ele chama um método correspondente.

Além do Parser, temos constantes e funções para ajudar o tratamento dos logs.
'''

import re
import sys

#
# Globals 
#
PARTSIZE=9728000l

class LogParser:
	"""The LogParser"""
	def __init__(self,logfile=None):
		"""Gives the name of the log's filename.
		
		If logfile is not given or is None we will read from
		stdin
		"""
		# Initialization of instance-vars
		self.line=''
		self.__regexp={}
		self.__compileRegExes()
		# Abre o logfile
		if logfile is not None:
			self.__file = open(logfile,'r')
		else:
			self.__file = sys.stdin
			sys.stderr.write("Lendo da STDIN")
	
	def __compileRegExes(self):
		self.__regexp['CLIENT HELLO']=re.compile(r'CLIENT HELLO .*\bclient_hash\[(?P<hash>\w+)\]')
		self.__regexp['SENDING PART']=re.compile(r'SENDING PART hash\[(?P<hash>\w+)\] offset\[(?P<offset_inicial>\d+),(?P<offset_final>\d+)\]')
		self.__regexp['EMULE COMPRESSED DATA:1']=re.compile(r'EMULE COMPRESSED DATA hash\[(?P<hash>\w+)\] offset_start=(?P<offset_inicial>\d+) len=(?P<offset_compressed_length>\d+)')
		self.__regexp['EMULE COMPRESSED DATA:2']=re.compile(r'EMULE COMPRESSED DATA hash\[(?P<hash>\w+)\] offset\[(?P<offset_inicial>\d+),(?P<offset_compressed_length>\d+)\]')
		self.__regexp['FILE STATUS']=re.compile(r'FILE STATUS hash\[(?P<hash>\w+)\] len(=|\[)(?P<length>\d+)\]* bitmap=0x\[(?P<bitmap>\w*)\]')
		self.__regexp['FILE REQUEST ANSWER:1']=re.compile(r'FILE REQUEST ANSWER hash\[(?P<hash>\w+)\] filename\[(?P<filename>.*)\]\s*$')
		self.__regexp['FILE REQUEST ANSWER:2']=re.compile(r'FILE REQUEST ANSWER hash\[(?P<hash>\w+)\] filename\[(?P<filename>.*)\s*$')
		self.__regexp['PREFIX']=re.compile(r'(?P<timestamp>[\d-]+) (?P<connection>[\d:\.,]+)\[(?P<clientserver>\w)\] proto=0x\w\w msg_id=0x\w\w size=\d+ ')

	def __processLine(self):
		try:
			if self.line.find('CLIENT HELLO ANSWER') >= 0:
				match=self.__regexp['CLIENT HELLO'].search(self.line)
				self.onClientHelloAnswer( match.group('hash'))
			elif self.line.find('CLIENT HELLO') >= 0:
				match=self.__regexp['CLIENT HELLO'].search(self.line)
				self.onClientHello( match.group('hash'))
			elif self.line.find('SENDING PART') >= 0:
				match=self.__regexp['SENDING PART'].search(self.line)
				self.onSendingPart( match.group('hash'),
						    long(match.group('offset_inicial')),
						    long(match.group('offset_final')))
			elif self.line.find('EMULE COMPRESSED DATA') >= 0:
				match=self.__regexp['EMULE COMPRESSED DATA:1'].search(self.line)
				if match is None:
					match=self.__regexp['EMULE COMPRESSED DATA:2'].search(self.line)
				self.onSendingCompressed( match.group('hash'),
						    long(match.group('offset_inicial')),
						    long(match.group('offset_compressed_length')))
			elif self.line.find('FILE STATUS') >= 0:
				match=self.__regexp['FILE STATUS'].search(self.line)
				self.onFileStatus( match.group('hash'),
						    long(match.group('length')),
						    match.group('bitmap'))
			elif self.line.find('FILE REQUEST ANSWER') >= 0:
				match=self.__regexp['FILE REQUEST ANSWER:1'].search(self.line)
				if match is None:
					match=self.__regexp['FILE REQUEST ANSWER:2'].search(self.line)
				self.onFileRequestAnswer( match.group('hash'),
						    match.group('filename'))
			return
		except AttributeError, e:
			self.onError(self.line,e)
			#raise
		# Ops! It didn't match! Fallback
		self.onUnknown(self.line)
			
	
	def parse(self):
		"""Starts reading the file, processing its contents and
		calling the onTag-messages"""
		self.line = self.__file.readline()
		while self.line:
			self.line = self.line.rstrip()
			self.__processLine()
			# Reads the next line
			self.line =  self.__file.readline()
		self.onFinish()
	
	def onClientHelloAnswer(self,hash):
		pass

	def onClientHello(self,hash):
		pass

	def onSendingPart(self,hash,start,end):
		pass

	def onSendingCompressed(self,hash,start,length):
		pass
	
	def onFileStatus(self,hash,length,bitmap):
		pass
	
	def onFileRequestAnswer(self,hash,filename):
		pass

	def onError(self,offending_line,offending_exception):
		pass

	def onUnknown(self,line):
		pass
		
	def onFinish(self):
		pass
	
	def getPrefix(self):
		"""Returns a tuple containing the beging of the current line,
		if applicable or None.

		The tuple is like (long timestamp, str connection )
		"""
		match=self.__regexp['PREFIX'].search(self.line)
		if match is None:
			return None
		else:
			return (long(match.group('timestamp')),
				match.group('connection'),
				match.group('clientserver'))



def offset2fragment(offset):
	"""Returns the number of the fragment (starting from 0) where the given
	offset (starting from 0 too) is located"""
	return int(offset/PARTSIZE)

def quebra_em_fragmentos(start,length):
	'''Retorna um array de tuplas (fragmento,bytes)
	
	Lembrando: o primeiro fragmento, f[0] inicia em 0 e termina
	em PARTSIZE -1'''
	result=[]
	# Calcula os fragmentos iniciais e finais do pedido.
	# para o offset_final, subtraia 1
	fragmento_inicial = int(start/PARTSIZE)
	fragmento_final = int((start + length - 1)/PARTSIZE) 
	# Sanity Check
	if length <= 0:
		bytes = 0
		fragmento_final = fragmento_inicial
	# Primeiro fagmento - o mais complicado
	if fragmento_final == fragmento_inicial :
		bytes = length
		result.append( (fragmento_inicial,bytes) )
	elif fragmento_inicial != fragmento_final:
		# Esse pedidos cruza varios fragmentos
		# Contabiliza o primeiro fragmento
		bytes = (PARTSIZE * (fragmento_inicial+1)) - start
		result.append( (fragmento_inicial,bytes) )
		# contabiliza o restante, se existir
		for i in range(fragmento_inicial+1,fragmento_final):
			result.append( (i,PARTSIZE) )
		# e o final
		bytes = (start+length) - (PARTSIZE * fragmento_final)  
		result.append( (fragmento_final,bytes) )
	#else:
		#print #
	return result


class MyLogParser(LogParser):
	def __init__(self,filename=None):
		# Base class initialization
		LogParser.__init__(self,filename)

	def onClientHelloAnswer(self,hash):
		print "Client Hello Answer",hash

	def onClientHello(self,hash):
		print "Client Hello ",hash

	def onFileRequestAnswer(self,hash,filename):
		print "File Request Answer h[%s] n[%s]"% (hash, filename)

	def onSendingCompressed(self,hash,start,length):
		self.printPrefix()
		print "Sending Compressed h[%s] n[%s]"% (hash, length)

	def onSendingPart(self,hash,start,end):
		self.printPrefix()
		print "Sending Part h[%s] n[%ul,%ul]"% (hash, start,end)

	def onFileStatus(self,hash,length,bitmap):
		print "File Status " + hash
	
	def printPrefix(self):
		ts,addr,cs=self.getPrefix()
		print "ts[%ul]\taddr[%s]\t"%(ts,addr),

	def onError(self,offending_line,offending_exception):
		sys.stderr.write("ERROR:"+str(offending_exception)+ offending_line)

	def onFinish(self):
		pass



if __name__ == '__main__':
	parser=MyLogParser()
	try:
		parser.parse()
	finally:
		print parser.line
