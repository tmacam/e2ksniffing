#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
""" FirstPass - Dá uma primeira lida no log

Realiza uma primeira passada no log, extraindo informações
necessárias para geração de logs gerais e para scripts que
realizam uma segunda passada no log.

O log deve ser passado para essa script pela STDIN.
Ao final de sua execução teremos os seguintes arquivos:
session.{bdb,gdb,db}
hash.{bdb,gdbm,db}

$Id: FirstPass.py,v 1.5 2004-04-05 03:15:34 tmacam Exp $
"""

import sys
import LogParser
import shelve

class FirstPass(LogParser.LogParser):
	"""Runing a file into this parser will populate 2 dictionaries:
	    - sessions, with the format:
	    	session[addr] -> { 'user_hash': str,
				   'ts_begin'int,
				   'ts_end': int,
				   'hashes_bytes' :{str hash: int}}
	    - hashes, with the format:
	    	 hashes[hash] -> { 'names':[str],
		 		   'bytes': int}
	
	With these 2 dicts on can generate the folling statistics:
		- hash_names
		- hash_bytes
		- hash_sizes 
			(depends on SearchNames, hash_names, uniq_hashes_downloaded)
		- hash_bytes
		- uniq_hash_asked (hash_bytes[h] == 0)
		- uniq_hash_downloaded(hash_bytes[h] != 0)
		- uniq user_ids
		- userid_sessions
		- session_time (userID, sessionId/ timestamp+ips, duração)
		- session_bytes (userID, sessionID, bytes transferidos)
		- userid_hashes (userid_sessions, session)
		- userid_sizes

	NOTICE: we are using the tuple4/tcp endpoints's addresses as session
	identifier.
	"""
	def __init__(self,sessions={},hashes={},filename=None):
		"""Session and hashes should be dictionary-like structures."""
		# Base class initialization
		LogParser.LogParser.__init__(self,filename)
		
		# Now, our instance-menbers
		# session[ addr] -> {user_hash, ts_begin, ts_end, bytes,hash}
		self.sessions = sessions
		self.hashes = hashes
	
	def updateSessionTimestamps(self,addr,ts):
		"""Name says all. If this session is unknown,
		add it to the known sessions dict."""
		if not self.sessions.has_key(addr):
			self.sessions[addr] = { 'user_hash':	None,
						'ts_begin':	ts,
						'ts_end': 	ts,
						'hashes_bytes':	{}}
		# Updates the ts
		self.sessions[addr]['ts_end'] = ts

	def updateSessionByteHit(self,hash,length):
		"""Update the ByteHit of the current hash in the current
		session and in the hashid's.
		"""
		ts,addr = self.getPrefix()
		self.updateSessionTimestamps(addr,ts)
		# Updates session's byte hit
		if not self.sessions[addr]['hashes_bytes'].has_key(hash):
			self.sessions[addr]['hashes_bytes'][hash] = length
		else:
			self.sessions[addr]['hashes_bytes'][hash] += length
		# updates hashe's byte hit
		if not self.hashes.has_key(hash):
			self.hashes[hash] = { 'names':[], 'bytes': length}
		else:
			self.hashes[hash]['bytes'] += length

		
	
	def onClientHello(self,hash):
		ts,addr = self.getPrefix()
		self.updateSessionTimestamps(addr,ts)
		self.sessions[addr]['user_hash']=hash

	def onSendingCompressed(self,hash,start,length):
		self.updateSessionByteHit(hash,length)

	def onSendingPart(self,hash,start,end):
		self.updateSessionByteHit( hash, end - start)

	def onFileRequestAnswer(self,hash,filename):
		self.updateSessionByteHit( hash, 0)
		if filename not in self.hashes[hash]['names']:
			self.hashes[hash]['names'].append(filename)

	def onError(self,offending_line,offending_exception):
		sys.stderr.write("ERROR: %s\n\t%s" %(offending_exception,offending_line))

	def onFinish(self):
		pass



if __name__ == '__main__':
	sessions=shelve.open('sessions.shelve')
	hashes=shelve.open('hashes.shelve')
	parser=FirstPass(sessions,hashes)
	try:
		parser.parse()
	finally:
		print parser.line
		sessions.close()
		hashes.close()

