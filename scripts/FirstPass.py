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

$Id: FirstPass.py,v 1.8 2004-04-05 04:59:53 tmacam Exp $
"""

import sys
from cPickle import dump
import LogParser
import shelve

class FirstPass(LogParser.LogParser):
	"""Runing a file into this parser will populate 2 dictionaries:
	    - sessions, with the format:
	    	session[addr] -> { 'user_hash': str,
				   'user_client': str,
				   'user_server': str,
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
	def __init__(self,sessions,hashes,filename=None):
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
						'user_client':	None,
						'user_server':	None,
						'ts_begin':	ts,
						'ts_end': 	ts,
						'hashes_bytes':	{}}
		# Updates the ts
		self.sessions[addr]['ts_end'] = ts

	def updateSessionByteHit(self,hash,length):
		"""Update the ByteHit of the current hash in the current
		session and in the hashid's. Also link the session's
		client_hash either user_client or user_server
		"""
		ts,addr,cs = self.getPrefix()
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
		# Links client_hash to the right user_<hash>
		# See... connections can be started in both directions,
		# so we gotta figure who is really getting the data
		if self.sessions[addr].has_key('user_server'):
			# Link the stuff
			if cs == "S":
				# Server is receiving a data/response message, so...
				self.sessions[addr]['user_hash'] = \
					self.sessions[addr]['user_server'] 
					
			else:
				# the client is the one receiving the data...
				self.sessions[addr]['user_hash'] = \
					self.sessions[addr]['user_client'] 
			# remove these unneeded keys
			try:
				del self.sessions[addr]['user_client']
				del self.sessions[addr]['user_server']
			except:
				# Go figure what can happen...
				pass
			

			

		
	
	def onClientHelloAnswer(self,hash):
		"""Registers the ClientHash of the Client-Peer in the
		session. It will later be (possibly) associeated with
		the session's client_hash.
		"""
		ts,addr,cs = self.getPrefix()
		self.updateSessionTimestamps(addr,ts)
		self.sessions[addr]['user_client']=hash
	
	def onClientHello(self,hash):
		"""Registers the ClientHash of the Servent-Peer in the
		session. It will later be (possibly) associeated with
		the session's client_hash.
		"""
		ts,addr,cs = self.getPrefix()
		self.updateSessionTimestamps(addr,ts)
		self.sessions[addr]['user_server']=hash

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
	sessions={}	#shelve.open('sessions.shelve')
	hashes={}	#shelve.open('hashes.shelve')
	parser=FirstPass(sessions,hashes)
	try:
		parser.parse()
	finally:
		print parser.line
		dump(parser.sessions, open('sessions.pickle','w'))
		dump(parser.hashes, open('hashes.pickle','w'))
		#parser.sessions.close()
		#parser.hashes.close()

