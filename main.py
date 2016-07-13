#!/bin/python
# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:

import sys
import configparser
import logging
import readline
from client import Client

logger = logging.getLogger(__name__)

# clear current line, output text, show input line again
# FIXME: strip escape sequences from msg
PROMPT = '%s%s '
mode = '>'

PLAIN = '>'
STEALTH = '$'
GOLD = '#'

def prompt():
	return PROMPT % (nick, mode)

def show(msg):
	line = readline.get_line_buffer()
	sys.stdout.write("\r\033[K%s\r\n%s%s" % (msg, prompt(), line))
	sys.stdout.flush()

def print_help():
	print("commands: /help /quit /encrypt /plain /stealth /gold /status " \
			"/msg /enc /dec /encs /encr /q /say /me")

xmpp = None
if __name__ == "__main__":
	logging.basicConfig(level=logging.ERROR,
		                        format="%(levelname)-8s %(message)s")

	filename = "xmpp.cfg"
	config = configparser.SafeConfigParser()
	config.read(filename)
	jid = config.get("xmpp", "jid")
	password = config.get("xmpp", "password")
	room = config.get("xmpp", "room")
	nick = config.get("xmpp", "nick")
	try:
		key = config.get("xmpp", "key")
	except:
		key = None

	mode = GOLD if key is not None else PLAIN

	xmpp = Client(jid, password, room, nick, key)
	xmpp.register_plugin("xep_0030") # Service Discovery
	xmpp.register_plugin("xep_0045") # Multi-User Chat
	xmpp.register_plugin("xep_0199") # XMPP Ping
	xmpp.register_plugin("encrypt-im") # encrypted stealth MUC

	def muc_msg(msg, nick, jid, role, affiliation, stealth):
		if stealth:
			if msg.startswith("/me "):
				show("$ *** %s %s" % (nick, msg[4:]))
			else:
				show("$ <%s> %s" % (nick, msg))
		else:
			if msg.startswith("/me "):
				show("*** %s %s" % (nick, msg[4:]))
			else:
				show("<%s> %s" % (nick, msg))

	def muc_mention(msg, nick, jid, role, affiliation, stealth):
		if stealth:
			show("$ <<<%s>>> %s" % (nick, msg))
		else:
			show("<<<%s>>> %s" % (nick, msg))

	def priv_msg(msg, jid):
		show("<PRIV#%s> %s" % (jid, msg))

	def muc_online(jid, nick, role, affiliation, localjid):
		show("*** online: %s (%s; %s)" % (nick, jid, role))

	def muc_offline(jid, nick):
		show("*** offline: %s" % nick)

	xmpp.add_message_listener(muc_msg)
	xmpp.add_mention_listener(muc_mention)
	xmpp.add_online_listener(muc_online)
	xmpp.add_offline_listener(muc_offline)
	xmpp.add_private_listener(priv_msg)

	if xmpp.connect():
		xmpp.process(block=False)
	else:
		print("Unable to connect")
		sys.exit(1)

	readline.read_init_file()
	try:
		while True:
			line = input(prompt())
			if not line:
				continue
			msg = line.strip()
			if len(msg) == 0:
				continue
			if msg == "/help":
				print_help()
			elif msg == "/quit":
				break
			elif msg == "/encrypt" or msg == "/gold":
				if xmpp.key is None:
					print("no encryption key set")
				else:
					xmpp.encrypt = True
					mode = GOLD
			elif msg == "/plain":
				xmpp.encrypt = False
				mode = PLAIN
			elif msg == "/stealth":
				if xmpp.key is None:
					print("no encryption key set")
				else:
					mode = STEALTH
			elif msg == "/status":
				print("key %s, mode is %s" % ("available" if
						xmpp.key is not None else
						"not available", "plaintext" if
						mode == PLAIN else "gold" if
						mode == GOLD else "stealth" if
						mode == STEALTH else "strange"))
			elif msg.startswith("/msg "):
				nick, text = None, None
				try:
					nick = msg[5:msg[5:].index(" ") + 5] \
							.strip()
					text = msg[5 + len(nick) + 1:].strip()
				except ValueError as e:
					print("syntax error")
				if nick is not None:
					xmpp.msg_send(nick, text, True)
			elif msg.startswith("/enc "):
				text = msg[5:].strip()
				if xmpp.key is None:
					print("error: no key set")
				else:
					try:
						data = xmpp.encode(text)
						print(data)
					except Exception as e:
						print("exception: %s" % e)
			elif msg.startswith("/dec "):
				text = msg[5:].strip()
				if xmpp.key is None:
					print("error: no key set")
				else:
					try:
						data = xmpp.decode(text)
						print("'%s'" % data)
					except Exception as e:
						print("exception: %s" % e)
			elif msg.startswith("/encs "):
				text = msg[6:].strip()
				if xmpp.key is None:
					print("error: no key set")
				else:
					try:
						xmpp.muc_send(text, enc=True)
					except Exception as e:
						print("exception: %s" % e)
			elif msg.startswith("/q "):
				text = msg[3:].strip()
				if xmpp.key is None:
					print("error: no key set")
				else:
					try:
						xmpp.muc_send(text,
								stealth=True)
					except Exception as e:
						import traceback
						print("exception: %s" % e)
						traceback.print_exc()
			elif msg.startswith("/encr "):
				text = msg[6:].strip()
				if xmpp.key is None:
					print("error: no key set")
				else:
					try:
						data = xmpp.encode(text)
						xmpp.muc_send(data, enc=False)
						print("%s> %s" % (nick, data))
					except Exception as e:
						print("exception: %s" % e)
			elif msg.startswith("/say "):
				text = msg[5:].strip()
				xmpp.muc_send(text)
			elif msg[0] == "/" and not msg.startswith("/me "):
				print("unknown command")
			else:
				if mode == STEALTH:
					xmpp.muc_send(msg, stealth=True)
				else:
					xmpp.muc_send(msg)

	except KeyboardInterrupt: pass
	except EOFError: pass

	xmpp.disconnect()
