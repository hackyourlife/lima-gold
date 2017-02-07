# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:

import sleekxmpp
from sleekxmpp.xmlstream import ET
from time import time
import logging
import re

import encryptim

from Crypto.Cipher import AES
from Crypto import Random
import base64

encryptim.register()

class Client(sleekxmpp.ClientXMPP):
	mention_listeners = []
	private_listeners = []
	message_listeners = []
	online_listeners = []
	offline_listeners = []
	init_complete_listeners = []
	participants = {}

	PLAIN = 0
	ENCRYPTED = 1
	STEALTH = 2

	def __init__(self, jid, password, room, nick, key=None, log=None,
			history=False, encrypted_msg_info="[encrypted]", ipv6=True):
		sleekxmpp.ClientXMPP.__init__(self, jid, password)

		self.use_ipv6 = ipv6
		self.room = room
		self.nick = nick
		self.online = False
		self.history = history
		self.encrypted_msg_info = encrypted_msg_info

		if key is None:
			self.encrypt = False
			self.key = None
		else:
			self.encrypt = True
			self.key = key.encode('utf-8')

			# apply padding
			length = 32 - (len(self.key) % 32)
			self.key += bytes([length]) * length

		if not log is None:
			self.log = log
			self.log.name = __name__
		else:
			self.log = logging.getLogger(__name__)

		self.add_event_handler("session_start", self.start)
		self.add_event_handler("groupchat_message", self.muc_message)
		self.add_event_handler("message", self.message)
		self.add_event_handler("muc::%s::got_online" % self.room,
				self.muc_online)
		self.add_event_handler("muc::%s::got_offline" % self.room,
				self.muc_offline)

	def encode(self, msg):
		data = msg.encode('utf-8')
		iv = Random.new().read(AES.block_size)
		aes = AES.new(self.key, AES.MODE_CBC, iv)
		length = 16 - (len(data) % 16)
		data += bytes([length]) * length
		enc = aes.encrypt(data)
		return base64.b64encode(iv + enc).decode('ascii')

	def decode(self, msg):
		raw = base64.b64decode(msg)
		iv = raw[0:AES.block_size]
		msg = raw[AES.block_size:]
		aes = AES.new(self.key, AES.MODE_CBC, iv)
		data = aes.decrypt(msg)
		return data[:-data[-1]].decode('utf-8')

	def add_mention_listener(self, listener):
		self.mention_listeners += [ listener ]

	def add_message_listener(self, listener):
		self.message_listeners += [ listener ]

	def add_online_listener(self, listener):
		self.online_listeners += [ listener ]

	def add_offline_listener(self, listener):
		self.offline_listeners += [ listener ]

	def add_private_listener(self, listener):
		self.private_listeners += [ listener ]

	def add_init_complete_listener(self, listener):
		self.init_complete_listeners += [ listener ]

	def start(self, event):
		self.get_roster()
		self.send_presence()
		self.plugin['xep_0045'].joinMUC(self.room, self.nick,
				maxhistory="20" if self.history else "0",
				wait=True)

	def muc_message(self, msg):
		nick = msg['mucnick']
		jid = msg['from'].full
		role = None
		affiliation = None
		if len(nick) != 0:
			jid = self.plugin['xep_0045'].getJidProperty(self.room,
					nick, 'jid')
			try:
				jid = jid.full
			except:
				jid = ""
			if len(jid) == 0:
				jid = msg['from'].full
			role = self.plugin['xep_0045'].getJidProperty(self.room,
					nick, 'role')
			affiliation = self.plugin['xep_0045'].getJidProperty(
					self.room, nick, 'affiliation')
		echo = nick == self.nick
		body = msg['body']
		msgtype = self.PLAIN
		if len(msg['encrypted']['content']) != 0:
			if self.key is None:
				return
			data = msg['encrypted']['content']
			try:
				body = self.decode(data)
				msgtype = self.STEALTH
			except Exception as e:
				self.log.warn("exception while " \
						"decoding: %s" % e)
		if len(body) == 0:
			return
		if self.key is not None:
			try:
				XHTML_NS = 'http://www.w3.org/1999/xhtml'
				span = msg['html'].find('.//{%s}span[@data]' %
						XHTML_NS)
				if span is not None:
					data = span.attrib.get('data')
					body = self.decode(data)
					if len(body) == 0:
						body = msg['body']
					else:
						msgtype = self.ENCRYPTED
			except Exception as e:
				self.log.warn("exception while " \
						"decoding lima gold: " \
						"%s" % e)
		if body.startswith("%s:" % self.nick) or \
				body.startswith("%s " % self.nick) \
				and len(body) > len(self.nick) + 2:
			text = body[len(self.nick) + 1:].strip()
			if body[len(self.nick)] != ':' and text[0] == ':' \
					and len(text) > 2 and text[1] == ' ':
				text = text[1:].strip()
			for listener in self.mention_listeners:
				listener(msg=text, nick=nick, jid=jid,
						role=role,
						affiliation=affiliation,
						msgtype=msgtype,
						echo=echo,
						body=body)
		elif self.nick in re.split(r"\s|:|!|\?|,|;", body):
			for listener in self.mention_listeners:
				listener(msg=body, nick=nick, jid=jid,
						role=role,
						affiliation=affiliation,
						msgtype=msgtype,
						echo=echo,
						body=body)
		else:
			for listener in self.message_listeners:
				listener(msg=body, nick=nick,
						jid=jid, role=role,
						affiliation=affiliation,
						msgtype=msgtype,
						echo=echo)

	def message(self, msg):
		if msg['type'] in ('chat', 'normal'):
			text = msg['body']
			jid = msg['from'].full
			if len(text) == 0:
				return
			self.log.info("[PRIVATE] %s: '%s'" % (jid, text))
			for listener in self.private_listeners:
				listener(msg=text, jid=jid)

	def muc_online(self, presence):
		if presence['muc']['nick'] != self.nick:
			jid = presence['from'].full
			fulljid = jid
			if len(presence['muc']['jid'].full):
				fulljid = presence['muc']['jid'].full
			role = presence['muc']['role']
			nick = presence['muc']['nick']
			affiliation = presence['muc']['affiliation']
			self.participants[jid] = {'jid': fulljid,
					'role': role,
					'nick': nick,
					'affiliation': affiliation,
					'time': time()}
			self.log.info("online: %s: %s [%s]" % (fulljid, role,
					nick))
			for listener in self.online_listeners:
				listener(jid=fulljid, nick=nick, role=role,
						affiliation=affiliation,
						localjid=jid,
						info=not self.online)
		else:
			for listener in self.init_complete_listeners:
				listener()
			self.online = True

	def muc_offline(self, presence):
		if presence['muc']['nick'] != self.nick:
			jid = presence['from'].full
			if not jid in self.participants:
				return # workaround for strange presence
			nick = self.participants[jid]['nick']
			fulljid = self.participants[jid]['jid']
			del self.participants[jid]
			self.log.info("offline: %s: %s" % (fulljid, nick))
			for listener in self.offline_listeners:
				listener(jid=fulljid, nick=nick)

	def muc_send(self, msg, enc=None, stealth=False):
		if stealth and self.key is not None:
			self.muc_send_stealth(msg)
		elif (enc is None and self.encrypt or enc) \
				and self.key is not None:
			html = '<span data="%s">%s</span>' % (self.encode(msg),
					self.encrypted_msg_info)
			sleekxmpp.ClientXMPP.send_message(self, mto=self.room,
					mbody=self.encrypted_msg_info,
					mhtml=html, mtype='groupchat')
		else:
			sleekxmpp.ClientXMPP.send_message(self, mto=self.room,
					mbody=msg, mtype='groupchat')

	def muc_send_encrypted(self, msg, plain=None):
		if self.key is None:
			raise Exception("no encryption key!")
		if plain is None:
			plain = self.encrypted_msg_info
		html = '<span data="%s">%s</span>' % (self.encode(msg), plain)
		sleekxmpp.ClientXMPP.send_message(self, mto=self.room,
				mbody=plain, mhtml=html, mtype='groupchat')

	def muc_send_stealth(self, msg):
		message = self.Message(sto=self.room, stype='groupchat',
				sfrom=None)
		message['encrypted']['content'] = self.encode(msg)
		message.send()

	def msg_send(self, to, msg, muc):
		jid = to
		if muc:
			jid = "%s/%s" % (self.room, to)
		sleekxmpp.ClientXMPP.send_message(self, mto=jid, mbody=msg,
				mtype='chat')

	def set_role(self, nick, role):
		if not self.is_participant(nick):
			self.log.warn("trying to change role of non-existent" \
					" user '%s'" % nick)
			return False
		self.log.info("setting role for %s to %s" % (nick, role))
		return self.plugin['xep_0045'].setRole(self.room, nick, role)

	def kick(self, nick, reason=None):
		if not self.is_participant(nick):
			self.log.warn("trying to kick non-existent user '%s'" %
					nick)
			return False
		pr = "no reason" if reason is None else "reason: %s" % reason
		self.log.info("kicking %s (%s)" % (nick, pr))
		query = ET.Element("{http://jabber.org/protocol/muc#admin}query")
		item = ET.Element("item", {"role": "none", "nick": nick})
		if not reason is None:
			rxml = ET.Element("reason")
			rxml.text = reason
			item.append(rxml)
		query.append(item)
		iq = self.makeIqSet(query)
		iq['to'] = self.room
		result = iq.send()
		if result is False or result['type'] != 'result':
			raise ValueError
		return True

	def is_participant(self, nick):
		return not self.get_participant(nick) is None

	def get_participant(self, nick):
		for jid in self.participants:
			participant = self.participants[jid]
			if participant["nick"] == nick:
				return participant
		return None

	def get_participants(self):
		return self.participants
