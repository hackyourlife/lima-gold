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
PROMPT = '> '
def show(msg):
	line = readline.get_line_buffer()
	sys.stdout.write("\r\033[K%s\r\n%s%s" % (msg, PROMPT, line))
	sys.stdout.flush()

def print_help():
	show("commands: /help /quit /encrypt /plain /status")

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

	PROMPT = "%s%s " % (nick, "#" if key is not None else ">")

	xmpp = Client(jid, password, room, nick, key)
	xmpp.register_plugin("xep_0030") # Service Discovery
	xmpp.register_plugin("xep_0045") # Multi-User Chat
	xmpp.register_plugin("xep_0199") # XMPP Ping

	def muc_msg(msg, nick, jid, role, affiliation):
		if msg.startswith("/me "):
			show("*** %s %s" % (nick, msg[4:]))
		else:
			show("<%s> %s" % (nick, msg))

	def muc_mention(msg, nick, jid, role, affiliation):
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
			line = input(PROMPT)
			if not line:
				continue
			msg = line.strip()
			if len(msg) == 0:
				continue
			if msg == "/help":
				print_help()
			elif msg == "/quit":
				break
			elif msg == "/encrypt":
				if xmpp.key is None:
					print("no encryption key set")
				else:
					xmpp.encrypt = True
					PROMPT = "%s# " % nick
			elif msg == "/plain":
				xmpp.encrypt = False
				PROMPT = "%s> " % nick
			elif msg == "/status":
				print("encryption %s" % ("enabled" if
						xmpp.encrypt else "disabled"))
			else:
				xmpp.muc_send(msg)

	except KeyboardInterrupt: pass
	except EOFError: pass

	xmpp.disconnect()
