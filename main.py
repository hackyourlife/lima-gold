#!/bin/python
# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:

import sys
import os
import configparser
import logging
import readline
import re
import hashlib
import rl
from optparse import OptionParser
from getpass import getpass
from client import Client

import datetime

_TIME_FORMAT = '%Y%m%dT%H:%M:%S'
_PRINT_FORMAT = '%H:%M:%S'

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

def localtime(at=None):
	if not at:
		at = now()
	if type(at) == float:
		at = datetime.datetime.fromtimestamp(at)
	st = at.strftime(_PRINT_FORMAT)
	return st

def utcnow():
	return datetime.datetime.utcnow()

def now():
	return datetime.datetime.now()

logger = logging.getLogger(__name__)

PROMPT = '%s%s '
mode = '>'
enable_bell = False
no_colors = False
show_timestamps = True

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
jid_regex = re.compile(r'[a-zA-Z0-9]+@(?:[a-zA-Z0-9]+\.)+[a-zA-Z0-9]+(?:/.*)?')

longest = 0
rpad = False
color_sequences = re.compile('\033\\[[^m]+?m')


COLORS = [ "[31m", "[32m", "[33m", "[34m", "[35m", "[36m", "[37m" ]
MENTION_COLOR = "[93m"
INPUT_COLOR = "[36m"
STEALTH_COLOR = "[96m"
ENCRYPTED_COLOR = "[33m" # "gold"

def get_nick_color(nick):
	md5 = hashlib.md5(nick.encode())
	return COLORS[md5.digest()[0] % len(COLORS) ]

def prompt():
	global xmpp
	return PROMPT % (xmpp.nick, mode)

def escape_vt(text):
	return text.replace("\033", "^[")

def show_raw(raw):
	if no_colors:
		raw = color_sequences.sub('', raw)
		rl.echo(raw)
	else:
		rl.echo("\033[0m%s" % raw, prompt_prefix="\033%s" % INPUT_COLOR)

def show(msg):
	show_raw(escape_vt(msg))

def show_input(msg):
	show_raw("\033%s%s %s%s\033[0m" % (INPUT_COLOR, localtime(),
			escape_vt(prompt()), escape_vt(msg)))

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
		"/msg": Help("/msg nick|jid message", "send a private message "
				"to \"nick\" or \"jid\"."),
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
		"/ls": Help("/ls [detail]", "list all users in the room"),
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
				"[ui]\n"
				"rpadnicks = False\n"
				"colors = True\n"
				"timestamps = True\n"
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
				"logfile: the log file for history logging.\n"
				"rpadnicks: pad nicks, such that all messages "
				"are aligned\n"
				"colors: enable coloring of messages\n"
				"timestamps: show timestamps"),
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
	show("commands: %s\nhelp topics: %s\nFor more information, type /help "
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
		show(text)
	else:
		show("no help entry found")

class NickCompleter(object):
	def __init__(self, xmpp):
		self.xmpp = xmpp

	def complete(self, text, state):
		if state == 0: # first time for this text: find nicks
			if text:
				participants = self.xmpp.get_participants()
				self.matches = [ participants[jid]["nick"] for \
						jid in participants if \
						participants[jid]["nick"] \
								.startswith(text) ]
			else:
				self.matches = []
		try:
			return self.matches[state]
		except IndexError:
			return None

xmpp = None
if __name__ == "__main__":
	logging.basicConfig(level=logging.ERROR,
		                        format="%(levelname)-8s %(message)s")

	parser = OptionParser()
	parser.add_option("-f", "--file", dest="file", help="Config file path")
	parser.add_option("-j", "--jid", dest="jid", help="JID")
	parser.add_option("-p", "--password", dest="password", help="Password")
	parser.add_option("-r", "--room", dest="room", help="Conference room")
	parser.add_option("-n", "--nick", dest="nick", help="Nick")
	parser.add_option("-k", "--key", dest="key", help="Encryption key")
	parser.add_option("-l", "--log", dest="log", help="Log file path")
	parser.add_option("-b", "--bell", dest="bell",
			action="store_true", help="Enable bell")
	parser.add_option("-B", "--no-bell", dest="bell",
			action="store_false", help="Disable bell")
	parser.add_option("-m", "--mode", dest="mode", help="Default mode")
	parser.add_option("-i", "--history", dest="history",
			action="store_true", help="Disable history on connect")
	parser.add_option("-H", "--no-history", dest="history",
			action="store_false", help="Disable history on connect")
	parser.add_option("-a", "--rpad", dest="rpad",
			action="store_true", help="rpad nicks")
	parser.add_option("-A", "--no-rpad", dest="rpad",
			action="store_false", help="Do not rpad nicks")
	parser.add_option("-c", "--colors", dest="colors",
			action="store_true", help="Disable colors")
	parser.add_option("-C", "--no-colors", dest="colors",
			action="store_false", help="Disable colors")
	parser.add_option("-t", "--timestamps", dest="Enable timestamps",
			action="store_true", help="Disable timestamps")
	parser.add_option("-T", "--no-timestamps", dest="timestamps",
			action="store_false", help="Disable timestamps")
	(options, args) = parser.parse_args()


	filenames = [ "xmpp.cfg", os.path.expanduser("~/.limagoldrc"),
			"/etc/limagold.conf" ]
	if options.file is not None:
		filenames = [ options.file ] + filenames

	config = configparser.SafeConfigParser()
	config.read(filenames)

	for section in [ "xmpp", "client", "ui" ]:
		if not config.has_section(section):
			config.add_section(section)

	if options.jid is not None:
		config.set("xmpp", "jid", options.jid)
	if options.password is not None:
		config.set("xmpp", "password", options.password)
	if options.room is not None:
		config.set("xmpp", "room", options.room)
	if options.nick is not None:
		config.set("xmpp", "nick", options.nick)
	if options.key is not None:
		config.set("xmpp", "key", options.key)
	if options.log is not None:
		config.set("client", "logfile", options.log)
	if options.bell is not None:
		config.set("client", "bell", str(options.bell))
	if options.mode is not None:
		config.set("client", "mode", options.mode)
	if options.history is not None:
		config.set("client", "history", str(options.history))
	if options.rpad is not None:
		config.set("ui", "rpadnicks", str(options.rpad))
	if options.colors is not None:
		config.set("ui", "colors", str(options.colors))
	if options.timestamps is not None:
		config.set("ui", "timestamps", str(options.timestamps))

	jid = config.get("xmpp", "jid")
	try:
		password = config.get("xmpp", "password")
	except:
		password = getpass("Password: ")
	room = config.get("xmpp", "room")
	nick = config.get("xmpp", "nick")
	key = config.get("xmpp", "key", fallback=None)
	logfile_name = config.get("client", "logfile", fallback="xmpp.log")
	enable_bell = config.getboolean("client", "bell", fallback=False)
	default_mode = config.get("client", "mode", fallback="plain")
	history = config.getboolean("client", "history", fallback=True)
	rpad = config.getboolean("ui", "rpadnicks", fallback=False)
	no_colors = not config.getboolean("ui", "colors", fallback=True)
	show_timestamps = config.getboolean("ui", "timestamps", fallback=True)

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
			longest = len(nick)

		return nick if not rpad else nick.rjust(longest, ' ')

	def muc_msg(msg, nick, jid, role, affiliation, msgtype, echo):
		nick = get_formatted_nick(nick);
		if enable_bell and not echo:
			sys.stdout.write("\007")
		color = INPUT_COLOR if echo else get_nick_color(nick)
		normal_color = INPUT_COLOR if echo else "[0m"
		t = localtime()
		timestamp = "%s " % t if show_timestamps else ""
		timestamp_nos = "%s" % t if show_timestamps else ""
		if msgtype == xmpp.STEALTH:
			if msg.startswith("/me "):
				show_raw("\033%s%s$\033%s*** %s\033%s %s" %
						(STEALTH_COLOR, timestamp_nos,
							color, escape_vt(nick),
							normal_color,
							escape_vt(msg[4:])))
			else:
				show_raw("\033%s%s$\033%s<%s>\033%s %s" %
						(STEALTH_COLOR, timestamp_nos,
							color, nick,
							normal_color, msg))
			log_msg("Q", msg, nick)
		elif msgtype == xmpp.ENCRYPTED:
			if msg.startswith("/me "):
				show_raw("\033%s%s#\033%s*** %s\033%s %s" %
						(ENCRYPTED_COLOR, timestamp_nos,
							color, escape_vt(nick),
							normal_color,
							escape_vt(msg[4:])))
			else:
				show_raw("\033%s%s#\033%s<%s>\033%s %s" %
						(ENCRYPTED_COLOR, timestamp_nos,
							color, escape_vt(nick),
							normal_color,
							escape_vt(msg)))
			log_msg("E", msg, nick)
		else:
			if msg.startswith("/me "):
				show_raw("\033%s%s\033%s*** %s\033%s %s" %
						(normal_color, timestamp, color,
							escape_vt(nick),
							normal_color,
							escape_vt(msg[4:])))
			else:
				show_raw("\033%s%s\033%s<%s>\033%s %s" %
						(normal_color, timestamp,
						color, escape_vt(nick),
						normal_color, escape_vt(msg)))
			log_msg("M", msg, nick)

	def muc_mention(msg, nick, jid, role, affiliation, msgtype, echo, body):
		nick = get_formatted_nick(nick);
		if enable_bell and not echo:
			sys.stdout.write("\007")
		color = get_nick_color(nick)
		msgcolor = INPUT_COLOR if echo else MENTION_COLOR
		timestamp = "\033%s%s " % (MENTION_COLOR, localtime()) if \
				show_timestamps else ""
		timestamp_nos = "\033%s%s" % (MENTION_COLOR, localtime()) if \
				show_timestamps else ""
		if msgtype == xmpp.STEALTH:
			show_raw("%s\033%s$\033%s<<<%s>>>\033%s " "%s\033[0m" %
					(timestamp_nos, msgcolor, color,
						nick, msgcolor, msg))
			log_msg("Q", body, nick)
		elif msgtype == xmpp.ENCRYPTED:
			show_raw("%s\033%s#\033%s<<<%s>>>\033%s " "%s\033[0m" %
					(timestamp_nos, msgcolor, color,
						nick, msgcolor, msg))
			log_msg("E", body, nick)
		else:
			show_raw("%s\033%s<<<%s>>>\033%s %s\033[0m" %
					(timestamp, color, nick, msgcolor, msg))
			log_msg("M", body, nick)

	def priv_msg(msg, jid):
		if enable_bell:
			sys.stdout.write("\007")
		timestamp = "%s " % localtime() if show_timestamps else ""
		show_raw("\033%s%s<PRIV#%s> %s\033[0m" % (MENTION_COLOR,
				timestamp, escape_vt(jid), escape_vt(msg)))

	def muc_online(jid, nick, role, affiliation, localjid, info):
		global longest

		if history:
			timestamp = "%s " % localtime() if show_timestamps \
					else ""
			show("%s*** online: %s (%s; %s)" % (timestamp, nick,
				jid, role))
		log_status("%s <%s> has joined" % (nick, jid))

		if len(nick) > longest:
			longest = len(nick)

	def muc_offline(jid, nick):
		timestamp = "%s " % localtime() if show_timestamps else ""
		show("%s*** offline: %s" % (timestamp, nick))
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
	readline.parse_and_bind("tab: complete")
	readline.set_completer(NickCompleter(xmpp).complete)
	rl.set_delete_input()

	try:
		while True:
			if not no_colors:
				sys.stdout.write("\033%s" % INPUT_COLOR)
				sys.stdout.flush()
			line = input(prompt())
			if not line:
				continue
			msg = line.strip()
			if len(msg) == 0:
				continue
			if msg == "/help":
				show_input(msg)
				print_help()
			elif msg.startswith("/help "):
				show_input(msg)
				text = msg[6:].strip()
				show_help(text)
			elif msg == "/quit":
				show_input(msg)
				break
			elif msg == "/encrypt" or msg == "/gold":
				show_input(msg)
				if xmpp.key is None:
					show("no encryption key set")
				else:
					xmpp.encrypt = True
					mode = GOLD
			elif msg == "/plain":
				show_input(msg)
				xmpp.encrypt = False
				mode = PLAIN
			elif msg == "/stealth":
				show_input(msg)
				if xmpp.key is None:
					show("no encryption key set")
				else:
					mode = STEALTH
			elif msg == "/status":
				show_input(msg)
				show("key %s, mode is %s" % ("available" if
						xmpp.key is not None else
						"not available", "plaintext" if
						mode == PLAIN else "gold" if
						mode == GOLD else "stealth" if
						mode == STEALTH else "strange"))
			elif msg.startswith("/msg "):
				show_input(msg)
				nick, text = None, None
				try:
					nick = msg[5:msg[5:].index(" ") + 5] \
							.strip()
					text = msg[5 + len(nick) + 1:].strip()
				except ValueError as e:
					show("syntax error")
				participants = xmpp.get_participants()
				nicks = [ participants[jid]["nick"]
						for jid in participants ]
				if not nick in nicks:
					if jid_regex.match(nick) is not None:
						xmpp.msg_send(nick, text, False)
					else:
						show("error: no such user")
				else:
					xmpp.msg_send(nick, text, True)
			elif msg.startswith("/enc "):
				show_input(msg)
				text = msg[5:].strip()
				if xmpp.key is None:
					show("error: no key set")
				else:
					try:
						data = xmpp.encode(text)
						show(data)
					except Exception as e:
						show("exception: %s" % e)
			elif msg.startswith("/dec "):
				show_input(msg)
				text = msg[5:].strip()
				if xmpp.key is None:
					show("error: no key set")
				else:
					try:
						data = xmpp.decode(text)
						show("'%s'" % data)
					except Exception as e:
						show("exception: %s" % e)
			elif msg.startswith("/e "):
				text = msg[3:].strip()
				if xmpp.key is None:
					show("error: no key set")
				else:
					try:
						xmpp.muc_send(text, enc=True)
					except Exception as e:
						show("exception: %s" % e)
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
				show_input(msg)
				show("bell is %s" % ("enabled" if enable_bell
					else "disabled"))
			elif msg.startswith("/bell "):
				show_input(msg)
				text = msg[6:].strip()
				if text == "on":
					enable_bell = True
					show("bell is now enabled")
				elif text == "off":
					enable_bell = False
					show("bell is now disabled")
				else:
					show("syntax error")
			elif msg == "/ls":
				show_input(msg)
				participants = xmpp.get_participants()
				nicks = sorted([ participants[jid]["nick"]
						for jid in participants ])
				show("currently %d participants: %s" %
						(len(nicks), ", ".join(nicks)))
			elif msg == "/ls detail":
				show_input(msg)
				participants = xmpp.get_participants()
				nicks = sorted([ "%s (%s)" %
						(participants[jid]["nick"], jid)
						for jid in participants ])
				show("currently %d participants: %s" %
						(len(nicks), ", ".join(nicks)))
			elif msg[0] == "/" and not msg.startswith("/me "):
				show_input(msg)
				show("unknown command")
			else:
				if mode == STEALTH:
					xmpp.muc_send(msg, stealth=True)
				else:
					xmpp.muc_send(msg)

	except KeyboardInterrupt: pass
	except EOFError: pass

	sys.stdout.write("\033[0m")
	sys.stdout.flush()

	xmpp.disconnect()
