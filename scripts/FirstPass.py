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

$Id: FirstPass.py,v 1.10 2004-04-14 13:26:24 tmacam Exp $
"""

import sys
from cPickle import dump
import LogParser
import shelve

class FirstPass(LogParser.LogParser):
	"""Runing a file into this parser will populate 2 dictionaries:
	    - sessions, with the format:
	    	sessions[addr] -> { 'user_hash': str,
				   'user_client': str,
				   'user_server': str,
				   'ts_begin'int,
				   'ts_end': int,
				   'hashes_bytes' :{str hash: int}}
	    - hashes, with the format:
	    	 hashes[hash] -> { 'names':[str],
		 		   'bytes': int}
	
	Session statistics only refer to FINISHED sessions. Unfinished
	sessions statistics can be obtained with the sessions attribute.

	HashId statistics refer to the WHOLE observed logs, regardless 
	of whether they happend in finished or unfinished sessions.
	
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
	identifier. Colisions may occur.
	"""
	def __init__(self,sessions,hashes,filename=None):
		"""Session and hashes should be dictionary-like structures."""
		# Base class initialization
		LogParser.LogParser.__init__(self,filename)
		
		# Now, our instance-menbers
		# session[ addr] -> {user_hash, ts_begin, ts_end, bytes,hash}
		self.closed_sessions = sessions
		self.sessions = {}
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
		# Updates the ts - store it in the shelve / dict
		sess = self.sessions[addr]
		sess['ts_end'] = ts
		self.sessions[addr] = sess
		

	def updateSessionByteHit(self,hash,length):
		"""Update the ByteHit of the current hash in the current
		session and in the hashid's. Also link the session's
		client_hash either user_client or user_server
		"""
		ts,addr,cs = self.getPrefix()
		self.updateSessionTimestamps(addr,ts)
		# Updates session's byte hit
		sess = self.sessions[addr]
		if not sess['hashes_bytes'].has_key(hash):
			sess['hashes_bytes'][hash] = length
		else:
			sess['hashes_bytes'][hash] += length
		self.sessions[addr] = sess
		
		# updates hashe's byte hit
		if not self.hashes.has_key(hash):
			self.hashes[hash] = { 'names':[], 'bytes': length}
		else:
			h = self.hashes[hash]
			h['bytes'] += length
			self.hashes[hash] = h
		# Links client_hash to the right user_<hash>
		# See... connections can be started in both directions,
		# so we gotta figure who is really getting the data
		if self.sessions[addr].has_key('user_server'):
			sess = self.sessions[addr]
			# Set sess['user_hash'] according to who is receiving
			# data
			if cs == "S":
				# Server is receiving a data/response message
				sess['user_hash'] = sess['user_server'] 
					
			else:
				# the client is the one receiving the data...
				sess['user_hash'] = sess['user_client'] 
			# remove these unneeded keys
			try:
				del sess['user_client']
				del sess['user_server']
			except:
				# Go figure what can happen...
				pass
			self.sessions[addr] = sess
			

			
	def onConnectionClosed(self,timestamp,connection):
		"""Removes a session from the known sessions dict
		and add it to the closed sessions dict"""
		try:
			sess = self.sessions[connection]
			del self.sessions[connection]
			self.closed_sessions[connection] = sess
			#sys.stdout.write("Closed session: "+connection+"\n")
		except KeyError:
			#sys.stderr.write("Unknown session: "+connection+"\n")
			pass
		
	
	def onClientHelloAnswer(self,hash):
		"""Registers the ClientHash of the Client-Peer in the
		session. It will later be (possibly) associeated with
		the session's client_hash.
		"""
		ts,addr,cs = self.getPrefix()
		self.updateSessionTimestamps(addr,ts)
		sess = self.sessions[addr]
		sess['user_client']=hash
		self.sessions[addr] = sess
	
	def onClientHello(self,hash):
		"""Registers the ClientHash of the Servent-Peer in the
		session. It will later be (possibly) associeated with
		the session's client_hash.
		"""
		ts,addr,cs = self.getPrefix()
		self.updateSessionTimestamps(addr,ts)
		sess = self.sessions[addr]
		sess['user_server']=hash
		self.sessions[addr] = sess

	def onSendingCompressed(self,hash,start,length):
		self.updateSessionByteHit(hash,length)

	def onSendingPart(self,hash,start,end):
		self.updateSessionByteHit( hash, end - start)

	def onFileRequestAnswer(self,hash,filename):
		self.updateSessionByteHit( hash, 0)
		if filename not in self.hashes[hash]['names']:
			h = self.hashes[hash]
			h['names'].append(filename)
			self.hashes[hash] = h

	def onError(self,offending_line,offending_exception):
		sys.stderr.write("ERROR: %s\n\t%s" %(offending_exception,offending_line))

	def onFinish(self):
		pass



if __name__ == '__main__':
	closed_sessions=shelve.open('sessions.shelve')
	saved_hashes=shelve.open('hashes.shelve')
	hashes={}
	parser=FirstPass(closed_sessions,hashes)
	try:
		parser.parse()
	finally:
		print parser.line
		#dump(parser.sessions, open('sessions.pickle','w'))
		#dump(parser.hashes, open('hashes.pickle','w'))
		print "Saving hash statistics"
		for h in hashes.keys():
			saved_hashes[h] = hashes[h]
		closed_sessions.close()
		saved_hashes.close()

