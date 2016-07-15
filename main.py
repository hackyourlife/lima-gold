#!/bin/python
# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:

import sys
import configparser
import logging
import readline
import re
from client import Client

import datetime

_TIME_FORMAT = '%Y%m%dT%H:%M:%S'

def time(at=None):
	"""Stringify time in ISO 8601 format."""
	if not at:
		at = utcnow()
	if type(at) == float:
		at = datetime.datetime.fromtimestamp(at)
	st = at.strftime(_TIME_FORMAT)
	tz = at.tzinfo.tzname(None) if at.tzinfo else 'UTC'
	st += ('Z' if tz == 'UTC' else tz)
	return st

def utcnow():
	return datetime.datetime.utcnow()

logger = logging.getLogger(__name__)

PROMPT = '%s%s '
mode = '>'
enable_bell = False

PLAIN = '>'
STEALTH = '$'
GOLD = '#'

xmpp = None

encrypted_message_info = "[Diese Nachricht ist nur für Lima-Gold-Mitglieder " \
		"lesbar. Mehr auf lima-city.de/gold]"
encrypted_link_info = "[Dieser Link ist nur für Lima-Gold-Mitglieder lesbar. " \
		"Mehr auf lima-city.de/gold]"
encrypted_section_info = "[Dieser Teil der Nachricht ist nur für " \
		"Lima-Gold-Mitglieder lesbar. Mehr auf lima-city.de/gold]"

url_regex = re.compile(r'(https?|ftps?|ssh|sftp|irc|xmpp)://([a-zA-Z0-9]+)')

longest = 0
rpad = False

def prompt():
	global xmpp
	return PROMPT % (xmpp.nick, mode)

# clear current line, output text, show input line again
# FIXME: strip escape sequences from msg
def show(msg):
	line = readline.get_line_buffer()
	msg = msg.replace("\033", "^[")
	sys.stdout.write("\r\033[K%s\r\n%s%s" % (msg, prompt(), line))
	sys.stdout.flush()

class Help(object):
	def __init__(self, usage=None, info=None, see=[], topic=None):
		self.iscommand = usage is not None
		self.usage = usage
		self.info = info
		self.see = see

online_help = { "/help": Help("/help [command]", "shows help"),
		"/quit": Help("/quit", "quit the client"),
		"/encrypt": Help("/encrypt", "switch to encrypted (gold) mode. "
				"Everyone will see, that there was a message, "
				"but only users with the key can read them",
				see=["/plain", "/stealth", "/status", "modes"]),
		"/plain": Help("/plain", "switch to plaintext mode. This is the"
				" mode, every XMPP client supports.",
				see=["/encrypt", "/stealth", "/status",
					"modes"]),
		"/gold": Help("/gold", "alias for /encrypt", see=["/encrypt",
				"/stealth", "/status", "modes"]),
		"/stealth": Help("/stealth", "switch to stealth mode. Messages "
				"are sent encrypted and regular XMPP clients "
				"will not see the message at all",
				see=["/encrypt", "/plain", "/status", "modes"]),
		"/status": Help("/status", "show the current status.",
				see=["/encrypt", "/plain", "/stealth",
					"modes"]),
		"/msg": Help("/msg nick message", "send a private message to "
				"\"nick\"."),
		"/enc": Help("/enc text", "encrypt text and display the result "
				"locally. Probably only useful for debugging.",
				see=["/dec", "/encr"]),
		"/dec": Help("/dec text", "decrypt text and display the result "
				"locally. Probably only useful for debugging.",
				see=["/enc", "/encr"]),
		"/encr": Help("/encr text", "encrypt text in the same way as "
				"/enc does, but send the result unencrypted "
				"over XMPP. Probably only useful to annoy "
				"someone.", see=["/enc", "/dec"]),
		"/e": Help("/e text", "send encrypted text, exactly in the same"
				"way as in the \"encrypt\" mode, but without "
				"switching the mode.", see=["/encrypt"]),
		"/p": Help("/p text", "send plain text, exactly in the same "
				"way as in the \"plain\" mode, but without "
				"switching the mode.", see=["/plain"]),
		"/q": Help("/q text", "send text quietly (stealth), exactly in "
				"the same way as in the \"stealth\" mode, but "
				"without switching the mode.",
				see=["/stealth"]),
		"/say": Help("/say text", "send text literally. This allows to "
				"start a message with a \"/\"."),
		"/me": Help("/me text", "send a message starting with \"/me\". "
				"You know, why this might be useful..."),
		"/bell": Help("/bell [on|off]", "sets or shows the usage of the"
				" terminal's bell. If enabled, the bell will "
				"ring if a message is received."),
		"/es": Help("/es plain$encrypted", "send a message whose plain "
				"section is sent unmodified, but the encrypted "
				"section is replaced with a [censored] message "
				"for all normal clients. To escape the "
				"separator character (\"$\") prefix it with a "
				"\"for the cheat, set \\$21 = $33\".",
				see=["/e", "/eq", "/el"]),
		"/eq": Help("/eq plain$encrypted", "send a message whose plain "
				"section is sent unmodified, but the encrypted "
				"section is completely removed for all normal "
				"clients. To escape the separator character "
				"(\"$\") prefix it with a \"\\\", e.g. "
				"\"for the cheat, set \\$21 = $33\".",
				see=["/e", "/es", "/el"]),
		"/el": Help("/el text", "send a message where everything "
				"starting at the first link is [encrypted].",
				see=["/e", "/es", "/eq"]),
		"modes": Help(topic="Modes", info="There exist 3 different "
				"modes of operation: plaintext, encrypted and "
				"stealth mode. They influence how messages are "
				"sent and if a regular client can see and/or "
				"read them. The current mode is indicated by "
				"the last character of the prompt.\n"
				"> = plaintext, # = encrypted, $ = stealth",
				see=["/plain", "/encrypt", "/stealth",
					"/status"]),
		"config": Help(topic="Configuration file", info="This clinet "
				"can be configured with a configuration file "
				"called xmpp.cfg and located in the current "
				"directory. The syntax is like a plain ini "
				"file: there are multiple sections, wich are "
				"started with a \"[section]\" and multiple "
				"values inside a section, one key/value pair "
				"per line.\n"
				"\n"
				"The full list of all configurable options:\n"
				"[xmpp]\n"
				"jid = account@jabber.server\n"
				"password = secret\n"
				"room = room@conference.jabber.server\n"
				"nick = Me\n"
				"key = secret\n"
				"\n"
				"[client]\n"
				"bell = False\n"
				"history = True\n"
				"mode = plain\n"
				"logfile = xmpp.log\n"
				"\n"
				"The options have the following meaning:\n"
				"jid: the jid of the jabber account.\n"
				"password: the account's password. This is "
				"optional. If it is missing, the client will "
				"ask on startup.\n"
				"room: the jid of the MUC room to join.\n"
				"nick: the nick you would like to use in the "
				"room.\n"
				"key: the encryption key for all the encrypted "
				"messages.\n"
				"bell: if this is enabled, the client will "
				"output a bell character each time a new "
				"message is received.\n"
				"history: if this is enabled, the client will "
				"try to get 20 lines of history after joining "
				"the room.\n"
				"mode: the default mode. It can be \"plain\", "
				"\"encrypt\" or \"stealth\". This has the same "
				"effect as if you enter a /plain, /encrypt or "
				"/stealth command by hand at each start.\n"
				"logfile: the log file for history logging."),
		"about": Help(topic="About", info="This client was written to "
				"allow private group chats in public muc "
				"rooms. The encrypted mode was invented to "
				"show other participants, that a conversation "
				"is going on, and to show them, that they "
				"have no chance to participate. The stealth "
				"mode was invented to hide the fact, that there"
				" is a conversation at all. To make this "
				"possible, the XMPP protocol was extended, "
				"such that regular clients silently ignore the "
				"stealth messages, but the conference server "
				"still distributes them to all clients.")
		}

def print_help():
	commands = " ".join(sorted([ key for key in online_help.keys() \
			if online_help[key].iscommand ]))
	topics = " ".join(sorted([ key for key in online_help.keys() \
			if not online_help[key].iscommand ]))
	print("commands: %s\nhelp topics: %s\nFor more information, type /help "
			"<command|topic>" % (commands, topics))

def show_help(subject):
	if subject in online_help:
		hlp = online_help[subject]
		if hlp.iscommand:
			text = "COMMAND: %s\nINFO: %s" % (hlp.usage, hlp.info)
		else:
			text = hlp.info
		if len(hlp.see) > 0:
			text += "\nSEE ALSO: %s" % ", ".join(hlp.see)
		print(text)
	else:
		print("no help entry found")

xmpp = None
if __name__ == "__main__":
	logging.basicConfig(level=logging.ERROR,
		                        format="%(levelname)-8s %(message)s")

	filename = "xmpp.cfg"
	config = configparser.SafeConfigParser()
	config.read(filename)
	jid = config.get("xmpp", "jid")
	try:
		password = config.get("xmpp", "password")
	except:
		import getpass
		password = getpass.getpass("Password: ")
	room = config.get("xmpp", "room")
	nick = config.get("xmpp", "nick")
	key = config.get("xmpp", "key", fallback=None)
	logfile_name = config.get("client", "logfile", fallback="xmpp.log")
	enable_bell = config.getboolean("client", "bell", fallback=False)
	default_mode = config.get("client", "mode", fallback="plain")
	history = config.getboolean("client", "history", fallback=True)
	rpad = config.getboolean("ui", "rpadnicks", fallback=False)

	mode = GOLD if key is not None else PLAIN

	xmpp = Client(jid, password, room, nick, key, history=history,
			encrypted_msg_info=encrypted_message_info)
	xmpp.register_plugin("xep_0030") # Service Discovery
	xmpp.register_plugin("xep_0045") # Multi-User Chat
	xmpp.register_plugin("xep_0199") # XMPP Ping
	xmpp.register_plugin("encrypt-im") # encrypted stealth MUC

	if default_mode == "plain" or key is None:
		xmpp.encrypt = False
		mode = PLAIN
	elif default_mode == "gold" or default_mode == "encrypt":
		xmpp.encrypt = True
		mode = GOLD
	elif default_mode == "stealth":
		xmpp.encrypt = False
		mode = STEALTH

	logfile = open(logfile_name, "a")

	def log_msg(msgtype, msg, nick):
		nick = get_formatted_nick(nick);
		t = time()
		lines = msg.count("\n")
		line = "%sR %s %03d <%s> %s" % (msgtype, t, lines, nick, msg)
		try:
			logfile.write("%s\n" % line)
			logfile.flush()
		except Exception as e:
			show("exception while writing log: %s" % e)

	def log_status(info):
		t = time()
		lines = info.count("\n")
		line = "MI %s %03d %s" % (t, lines, info)
		try:
			logfile.write("%s\n" % line)
			logfile.flush()
		except Exception as e:
			show("exception while writing log: %s" % e)

	def get_formatted_nick(nick):
		global longest
		global rpad
		if rpad and len(nick) > longest:
			longest = len(nick) + 1

		return nick if not rpad else nick.rjust(longest, ' ')

	def muc_msg(msg, nick, jid, role, affiliation, msgtype, echo):
		nick = get_formatted_nick(nick);
		if enable_bell and not echo:
			sys.stdout.write("\007")
		if msgtype == xmpp.STEALTH:
			if not echo:
				if msg.startswith("/me "):
					show("$ *** %s %s" % (nick, msg[4:]))
				else:
					show("$ %s: %s" % (nick, msg))
			log_msg("Q", msg, nick)
		else:
			if not echo:
				if msg.startswith("/me "):
					show("*** %s %s" % (nick, msg[4:]))
				else:
					show("%s: %s" % (nick, msg))
			log_msg("M" if msgtype == xmpp.PLAIN else "E", msg,
					nick)

	def muc_mention(msg, nick, jid, role, affiliation, msgtype, echo):
		nick = get_formatted_nick(nick);
		if enable_bell and not echo:
			sys.stdout.write("\007")
		if msgtype == xmpp.STEALTH:
			if not echo:
				show("$ <<<%s>>> %s" % (nick, msg))
			log_msg("Q", "%s: %s" % (xmpp.nick, msg), nick)
		else:
			if not echo:
				show("<<<%s>>> %s" % (nick, msg))
			log_msg("M" if msgtype == xmpp.PLAIN else "E",
					"%s: %s" % (xmpp.nick, msg), nick)

	def priv_msg(msg, jid):
		if enable_bell:
			sys.stdout.write("\007")
		show("<PRIV#%s> %s" % (jid, msg))

	def muc_online(jid, nick, role, affiliation, localjid):
		show("*** online: %s (%s; %s)" % (nick, jid, role))
		log_status("%s <%s> has joined" % (nick, jid))

	def muc_offline(jid, nick):
		show("*** offline: %s" % nick)
		log_status("%s has left" % nick)

	def muc_joined():
		log_status('You have joined as "%s"' % xmpp.nick)
		show('You have joined as "%s"' % xmpp.nick)

	xmpp.add_message_listener(muc_msg)
	xmpp.add_mention_listener(muc_mention)
	xmpp.add_online_listener(muc_online)
	xmpp.add_offline_listener(muc_offline)
	xmpp.add_private_listener(priv_msg)
	xmpp.add_init_complete_listener(muc_joined)

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
			elif msg.startswith("/help "):
				text = msg[6:].strip()
				show_help(text)
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
			elif msg.startswith("/e "):
				text = msg[3:].strip()
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
						print("exception: %s" % e)
			elif msg.startswith("/p "):
				text = msg[3:].strip()
				xmpp.muc_send(text, enc=False)
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
			elif msg.startswith("/es "):
				text = msg[4:].strip()
				plain_text = ""
				cipher_text = ""
				cipher = False
				escape = False
				for c in text:
					if cipher:
						cipher_text += c
					elif escape:
						escape = False
						plain_text += c
					elif c == "\\":
						escape = True
					elif c == "$":
						cipher = True
					else:
						plain_text += c
				plain_msg = "%s %s" % (plain_text.strip(),
						encrypted_section_info)
				cipher_msg = "%s%s" % (plain_text, cipher_text)
				xmpp.muc_send_encrypted(cipher_msg, plain_msg)
			elif msg.startswith("/eq "):
				text = msg[4:].strip()
				plain_text = ""
				cipher_text = ""
				cipher = False
				escape = False
				for c in text:
					if cipher:
						cipher_text += c
					elif escape:
						escape = False
						plain_text += c
					elif c == "\\":
						escape = True
					elif c == "$":
						cipher = True
					else:
						plain_text += c
				plain_msg = plain_text.strip()
				cipher_msg = "%s%s" % (plain_text, cipher_text)
				xmpp.muc_send_encrypted(cipher_msg, plain_msg)
			elif msg.startswith("/el "):
				text = msg[4:].strip()
				match = url_regex.search(text)
				if match is not None:
					msg = text[:match.start()]
					url = text[match.start():]
					plain_msg = "%s %s" % (msg.strip(),
							encrypted_link_info)
					cipher_msg = "%s%s" % (msg, url)
					xmpp.muc_send_encrypted(cipher_msg,
							plain_msg)
				else:
					xmpp.muc_send(msg)
			elif msg.startswith("/say "):
				text = msg[5:].strip()
				xmpp.muc_send(text)
			elif msg == "/bell":
				print("bell is %s" % ("enabled" if enable_bell
					else "disabled"))
			elif msg.startswith("/bell "):
				text = msg[6:].strip()
				if text == "on":
					enable_bell = True
					print("bell is now enabled")
				elif text == "off":
					enable_bell = False
					print("bell is now disabled")
				else:
					print("syntax error")
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
