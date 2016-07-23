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
import rp
import json
import rot
import espeak
from optparse import OptionParser
from getpass import getpass
from random import randint, shuffle
from client import Client
from api import noshow, help, get_help

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
decode_caesar = False
caesar_lang = None
msg_decode = False
espeak_voice = None

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
	# for now, just remove ESC and CSI chars
	return text.replace("\033", "^[").replace("\x9b", "CSI")

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
	def __init__(self, synopsis=None, description=None, args={}, info=None,
			see=[], topic=None):
		self.iscommand = synopsis is not None
		self.synopsis = synopsis
		self.description = description
		self.args = args
		self.info = info
		self.see = see
		self.topic = topic

online_help = {
		"/macro": Help("/macro text = replacement", "define a new "
				"macro. They are evaluated on the input text "
				"and can therefore invoke any command. However,"
				" you cannot override any command for "
				"manipulating macros.",
				see=["/dmacro", "/macros"]),
		"/dmacro": Help("/dmacro macro", "delete a macro.",
				see=["/macro", "/macros"]),
		"/macros": Help("/macros", "list all currently defined macros.",
				see=["/macro", "/dmacro"]),
		"/def": Help("/def text = replacement", "substitute all "
				"occurences of \"text\" by \"replacement\". "
				"This is similar to a macro, but more flexible,"
				" since it operates on substrings.",
				see=["/undef", "/defs"]),
		"/undef": Help("/undef def", "delete a definition.",
				see=["/def", "/defs"]),
		"/defs": Help("/defs", "lists all currently defined "
				"definitions.", see=["/def", "/undef"]),
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
			text = "SYNOPSIS\n  %s\n\nDESCRIPTION\n  %s" % \
					(hlp.synopsis, hlp.description)
			if len(hlp.args) > 0:
				a = "\n\n".join([ "  %s\n      %s" % \
							(arg, hlp.args[arg])
						for arg in hlp.args ])
				text += "\n\nARGUMENTS:\n%s" % a
		else:
			text = "TOPIC: %s\n\n%s" % (hlp.topic, hlp.info)
		if len(hlp.see) > 0:
			text += "\n\nSEE ALSO\n  %s" % ", ".join(hlp.see)
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

commands = {}
def add_command(name, callback):
	commands[name] = callback
	help_data = get_help(callback)
	if help_data is not None:
		online_help["/%s" % name] = Help(**help_data)

def parse_args(line, count=None):
	whitespace = [ "\t", "\r", "\n", " " ]
	args = []
	s = 0
	a = ""
	for i in range(len(line)):
		if count is not None and len(args) >= count:
			if len(line) > i:
				args += [ line[i:] ]
			break
		c = line[i]
		if s == 0: # init
			if c == '"':
				s = 3
			elif c == "'":
				s = 4
			elif c not in whitespace:
				s = 1
				a += c
		elif s == 1: # normal
			if c in whitespace:
				if len(a) > 0:
					args += [ a ]
					a = ""
				s = 2
			else:
				a += c
		elif s == 2: # whitespace
			if c == '"':
				s = 3
			elif c == "'":
				s = 4
			elif c not in whitespace:
				s = 1
				a += c
		elif s == 3: # "quote"
			if c == '"':
				s = 1
			elif c == "\\":
				s = 5
			else:
				a += c
		elif s == 4: # 'quote'
			if c == "'":
				s = 1
			elif c == "\\":
				s = 6
			else:
				a += c
		elif s == 5: # "quote": escape
			a += c
			s = 3
		elif s == 6: # 'quote': escape
			a += c
			s = 4
		else:
			raise Exception("unknown state!")
	if len(a) > 0:
		args += [ a ]
	return args

def execute_command(line):
	line = line.strip()
	if len(line) == 0:
		return False
	cmd = line.split(" ")[0]
	args = line[len(cmd) + 1:].strip()
	if len(args) == 0:
		args = None
	if cmd[0] != "/":
		return False
	cmd = cmd[1:]
	try:
		c = commands[cmd]
		if not hasattr(c, "noshow") or not c.noshow:
			show_input(line)
		if args is None:
			c()
		else:
			nargs = c.__code__.co_argcount
			args = parse_args(args, nargs - 1)
			c(*args)
	except KeyError:
		show('unknown command: "/%s"' % cmd)
		return (cmd, args)
	except TypeError:
		show("argument error")
	return True

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
	parser.add_option("-D", "--no-decode", dest="msgdecode", default=True,
			action="store_false", help="Disable message decoding")
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
	parser.add_option("-E", "--encrypted", dest="encrypted",
			help="Replacement text for encrypted messages")
	parser.add_option("-L", "--link", dest="link",
			help="Replacement text for encrypted links")
	parser.add_option("-S", "--section", dest="section",
			help="Replacement text for encrypted sections")
	parser.add_option("-J", "--no-join-log", dest="joinlog",
			action="store_false",
			help="Disable join-time join messages")
	parser.add_option("-V", "--voice", dest="voice", help="Voice name")
	(options, args) = parser.parse_args()


	xdg_dirs = os.getenv('XDG_CONFIG_HOME', os.path.expanduser("~/.config"))
	filenames = [ "/etc/limagold.conf",
			os.path.expanduser("~/.limagoldrc") ]
	for xdg_dir in xdg_dirs.split(":"):
		filenames += [ "%s/limagold.conf" % xdg_dir ]
	filenames += [ "xmpp.cfg" ]
	if options.file is not None:
		filenames += [ options.file ]

	config = configparser.SafeConfigParser()
	cfgfiles = config.read(filenames)

	for section in [ "xmpp", "client", "ui", "messages" ]:
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
	if options.joinlog is not None:
		config.set("client", "joinlog", str(options.joinlog))
	if options.rpad is not None:
		config.set("ui", "rpadnicks", str(options.rpad))
	if options.colors is not None:
		config.set("ui", "colors", str(options.colors))
	if options.timestamps is not None:
		config.set("ui", "timestamps", str(options.timestamps))
	if options.encrypted is not None:
		config.set("messages", "encrypted", options.encrypted)
	if options.link is not None:
		config.set("messages", "encrypted_link", options.link)
	if options.section is not None:
		config.set("messages", "encrypted_section", options.section)

	msg_decode = options.msgdecode
	espeak_voice = options.voice

	if espeak_voice is not None:
		import struct
		from pyaudio import PyAudio
		rate = espeak.initialize(espeak.AUDIO_OUTPUT_SYNCHRONOUS)
		espeak.set_voice(espeak_voice)
		pa = PyAudio()
		snd = pa.open(format=pa.get_format_from_width(2), channels=1,
				rate=rate, output=True)
		snd.start_stream()
		def synth_cb(samples, nsamples, events):
			result = bytes()
			for sample in samples[:nsamples]:
				result += struct.pack("=h", sample)
			snd.write(result)
			return 0
		espeak.set_synth_callback(synth_cb)

	jid = config.get("xmpp", "jid")
	try:
		password = config.get("xmpp", "password")
	except:
		password = getpass("Password: ")
	room = config.get("xmpp", "room")
	nick = config.get("xmpp", "nick")
	key = config.get("xmpp", "key", fallback=None)
	logfile_name = os.path.expanduser(config.get("client", "logfile",
			fallback="xmpp.log"))
	enable_bell = config.getboolean("client", "bell", fallback=False)
	default_mode = config.get("client", "mode", fallback="plain")
	history = config.getboolean("client", "history", fallback=True)
	join_log = config.getboolean("client", "joinlog", fallback=True)
	rpad = config.getboolean("ui", "rpadnicks", fallback=False)
	no_colors = not config.getboolean("ui", "colors", fallback=True)
	show_timestamps = config.getboolean("ui", "timestamps", fallback=True)
	decode_caesar = config.getboolean("ui", "caesar", fallback=False)
	caesar_lang = config.get("ui", "caesar_lang", fallback="en")
	encrypted_message_info = config.get("messages", "encrypted",
			fallback=encrypted_message_info)
	encrypted_link_info = config.get("messages", "encrypted_link",
			fallback=encrypted_link_info)
	encrypted_section_info = config.get("messages", "encrypted_section",
			fallback=encrypted_section_info)

	MENTION_COLOR = config.get("colors", "mention", fallback=MENTION_COLOR)
	INPUT_COLOR = config.get("colors", "input", fallback=INPUT_COLOR)
	STEALTH_COLOR = config.get("colors", "stealth", fallback=STEALTH_COLOR)
	ENCRYPTED_COLOR = config.get("colors", "encrypted",
			fallback=ENCRYPTED_COLOR)

	mode = GOLD if key is not None else PLAIN

	if not rot.is_supported(caesar_lang):
		caesar_lang = "en"

	xmpp = Client(jid, password, room, nick, key, history=history,
			encrypted_msg_info=encrypted_message_info)
	xmpp.register_plugin("xep_0030") # Service Discovery
	xmpp.register_plugin("xep_0045") # Multi-User Chat
	xmpp.register_plugin("xep_0199") # XMPP Ping
	xmpp.register_plugin("encrypt-im") # encrypted stealth MUC

	macros = {}
	if config.has_section("macros"):
		keys = config.options("macros")
		for macro in keys:
			macros[macro] = config.get("macros", macro)

	definitions = {}
	if config.has_section("definitions"):
		keys = config.options("definitions")
		for definition in keys:
			definitions[definition] = config.get("definitions",
					definition)

	regex_program = []
	if config.has_section("regex_programs"):
		program = config.get("regex_programs", "default", fallback=None)
		if program is not None:
			regex_program = json.loads(program)
	regex_default_program = rp.compile(regex_program)


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
		t = time()
		lines = msg.count("\n")
		line = "%sR %s %03d <%s> %s" % (msgtype, t, lines, nick, msg)
		try:
			logfile.write("%s\n" % line)
			logfile.flush()
		except Exception as e:
			show("exception while writing log: %s" % e)

	def log_privmsg(msg, jid):
		t = time()
		lines = msg.count("\n")
		line = "PR %s %03d <%s> %s" % (t, lines, jid, msg)
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

	bits_regex = re.compile(r"^[01\s]+$")
	lulu_regex = re.compile(r"^[lu\s]+$")
	hex_regex = re.compile(r"^[0-9a-fA-F]+$")
	strip_regex = re.compile(r"[:\s-]")
	is_printable = lambda x: x >= 32
	printable = lambda x: ord(".") if x < 32 else x
	bits2s = lambda b: "".join(chr(printable(int("".join(x), 2))) \
			for x in zip(*[iter(b)]*8))
	hex2s = lambda b: "".join(chr(printable(int("".join(x), 16))) \
			for x in zip(*[iter(b)]*2))
	lulu2s = lambda b: bits2s(b.replace("l", "1").replace("u", "0"))
	bits2p = lambda b: sum([ 1 for x in zip(*[iter(b)]*8) \
			if not is_printable(int("".join(x), 2)) ])

	def get_mode_name(msgtype):
		if msgtype == xmpp.STEALTH:
			return "stealth"
		elif msgtype == xmpp.ENCRYPTED:
			return "gold"
		else:
			return None

	def decode_msg(msg, nick, msgtype=None):
		msgmode = "" if msgtype is None or msgtype is xmpp.PLAIN else \
				"%s: " % get_mode_name(msgtype)

		if not msg_decode:
			if espeak_voice is not None:
				espeak.say("%s%s: %s" % (msgmode, nick, msg))
			return

		last = msg
		while True:
			stripped = strip_regex.sub("", msg)
			if bits_regex.match(stripped) is not None \
					and len(stripped) % 8 == 0:
				msg = bits2s(stripped)
				show("binary: %s" % msg)
				stripped = strip_regex.sub("", msg)
			if lulu_regex.match(stripped) is not None \
					and len(stripped) % 8 == 0:
				msg = lulu2s(stripped)
				show("lulu: %s" % msg)
				stripped = strip_regex.sub("", msg)
			if len(set(stripped)) == 2 and len(stripped) % 8 == 0 \
					and caesar_lang is not None:
				letters = list(set(stripped))
				binary1 = stripped.replace(letters[0], "0") \
						.replace(letters[1], "1")
				binary2 = stripped.replace(letters[0], "1") \
						.replace(letters[1], "0")
				b1 = bits2p(binary1)
				b2 = bits2p(binary2)
				candidate1 = bits2s(binary1)
				candidate2 = bits2s(binary2)
				freq = rot.default_frequencies(caesar_lang)
				l1 = sum([ 1 for x in set(candidate1) \
						if x in freq ])
				l2 = sum([ 1 for x in set(candidate2) \
						if x in freq ])
				c1 = rot.cost(candidate1, freq) if l1 > 0 \
						else None
				c2 = rot.cost(candidate2, freq) if l2 > 0 \
						else None
				if b1 < b2:
					c2 = None
				elif b2 < b1:
					c1 = None
				if not (c1 is None and c2 is None):
					if c1 is None:
						c1 = c2 + 1
					elif c2 is None:
						c2 = c1 + 1
					msg = candidate1 if c1 < c2 \
							else candidate2
					l = "%s%s" % ((letters[0], letters[1]) \
							if c1 < c2 else
							(letters[1], letters[0]))
					show("bin(%s): %s" % (l, msg))
				stripped = strip_regex.sub("", msg)
			if hex_regex.match(stripped) is not None \
					and len(stripped) % 2 == 0:
				if caesar_lang is not None:
					tmp = hex2s(stripped)
					freq = rot.default_frequencies(caesar_lang)
					l = sum([ 1 for x in set(tmp) \
							if x in freq ])
					if l != 0:
						msg = tmp
						show("hex: %s" % msg)
				else:
					msg = hex2s(stripped)
					show("hex: %s" % msg)
			if last == msg:
				break
			last = msg

		if decode_caesar:
			match = url_regex.search(msg)
			if match is None:
				try:
					result = rot.crackx(msg, caesar_lang,
							True)
					if result.text != msg:
						show("rot(%d): %s" % (result.n,
								result.text))
						msg = result.text
				except:
					pass

		# do not speak an url
		match = url_regex.search(msg)
		if match is not None and match.start() == 0:
			return

		if espeak_voice is not None:
			espeak.say("%s%s: %s" % (msgmode, nick, msg))

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
							color, escape_vt(nick),
							normal_color,
							escape_vt(msg)))
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

		decode_msg(msg, nick, msgtype)

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
						escape_vt(nick), msgcolor,
						escape_vt(msg)))
			log_msg("Q", body, nick)
		elif msgtype == xmpp.ENCRYPTED:
			show_raw("%s\033%s#\033%s<<<%s>>>\033%s " "%s\033[0m" %
					(timestamp_nos, msgcolor, color,
						escape_vt(nick), msgcolor,
						escape_vt(msg)))
			log_msg("E", body, nick)
		else:
			show_raw("%s\033%s<<<%s>>>\033%s %s\033[0m" %
					(timestamp, color, escape_vt(nick),
						msgcolor, escape_vt(msg)))
			log_msg("M", body, nick)

		decode_msg(msg, nick, msgtype)

	def priv_msg(msg, jid):
		if enable_bell:
			sys.stdout.write("\007")
		timestamp = "%s " % localtime() if show_timestamps else ""
		show_raw("\033%s%s<PRIV#%s> %s\033[0m" % (MENTION_COLOR,
				timestamp, escape_vt(jid), escape_vt(msg)))
		log_privmsg(msg, jid)

	def muc_online(jid, nick, role, affiliation, localjid, info):
		global longest

		if history or not info:
			timestamp = "%s " % localtime() if show_timestamps \
					else ""
			show("%s*** online: %s (%s; %s)" % (timestamp, nick,
				jid, role))

		if not info or join_log:
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

	def save_config():
		if len(cfgfiles) == 0:
			show("no config file")
			return
		cfgfile = cfgfiles[-1]
		cfg = configparser.SafeConfigParser()
		cfg.read(cfgfile)
		str_mode = "plain" if mode == PLAIN else "encrypt" \
				if mode == GOLD else "stealth"
		newcfg = {
				"client": {
					"mode": str_mode,
					"bell": str(enable_bell) },
				"ui": {
					"caesar": str(decode_caesar),
					"caesar_lang": str(caesar_lang) }
		}
		for section in newcfg:
			if not cfg.has_section(section):
				cfg.add_section(section)
			for option in newcfg[section]:
				cfg.set(section, option,
						newcfg[section][option])

		if not cfg.has_section("macros"):
			cfg.add_section("macros")
		for macro in cfg.options("macros"):
			cfg.remove_option("macros", macro)
		for macro in macros:
			cfg.set("macros", macro, macros[macro])
		if len(cfg.options("macros")) == 0:
			cfg.remove_section("macros")

		if not cfg.has_section("definitions"):
			cfg.add_section("definitions")
		for definition in cfg.options("definitions"):
			cfg.remove_option("definitions", definition)
		for definition in definitions:
			cfg.set("definitions", definition,
					definitions[definition])
		if len(cfg.options("definitions")) == 0:
			cfg.remove_section("definitions")

		if not cfg.has_section("regex_programs"):
			cfg.add_section("regex_programs")
		for regex in cfg.options("regex_programs"):
			cfg.remove_option("regex_programs", regex)
		if len(regex_program) != 0:
			cfg.set("regex_programs", "default",
					json.dumps(regex_program))
		if len(cfg.options("regex_programs")) == 0:
			cfg.remove_section("regex_programs")

		try:
			with open(cfgfile, "w") as f:
				cfg.write(f, True)
			show('wrote config to "%s"' % cfgfile)
		except Exception as e:
			show("exception: %s" % e)

	def send(msg):
		if mode == STEALTH:
			xmpp.muc_send(msg, stealth=True)
		else:
			xmpp.muc_send(msg)

	def send_mode(m, text):
		if m == "p":
			xmpp.muc_send(text, enc=False)
		elif m == "e":
			if xmpp.key is None:
				show("error: no key set")
			else:
				try:
					xmpp.muc_send(text, enc=True)
				except Exception as e:
					show("exception: %s" % e)
		elif m == "q":
			if xmpp.key is None:
				print("error: no key set")
			else:
				try:
					xmpp.muc_send(text,
							stealth=True)
				except Exception as e:
					show("exception: %s" % e)
		else:
			show("invalid argument: \"%s\"" % m)
		pass

	@help(synopsis="help [command|topic]",
		description="Shows help texts.",
		args={	"command": "a command you want to know something about",
			"topic":   "a help topic"})
	def _help(topic=None):
		if topic is None:
			print_help()
		else:
			show_help(topic)

	@help(synopsis="encrypt", description="Switch to encrypted (gold) "
			"mode. Everyone will see, that there was a message, but"
			" only users with the key can read them",
			see=["/plain", "/stealth", "/status", "modes"])
	def _encrypt():
		global mode
		if xmpp.key is None:
			show("no encryption key set")
		else:
			xmpp.encrypt = True
			mode = GOLD

	@help(synopsis="plain", description="Switch to plaintext mode. This is "
			"the mode, every XMPP client supports.",
			see=["/encrypt", "/stealth", "/status", "modes"])
	def _plain():
		global mode
		xmpp.encrypt = False
		mode = PLAIN

	@help(synopsis="stealth", description="Switch to stealth mode. Messages"
			" are sent encrypted and regular XMPP clients will not "
			"see the message at all",
			see=["/encrypt", "/plain", "/status", "modes"])
	def _stealth():
		global mode
		if xmpp.key is None:
			show("no encryption key set")
		else:
			mode = STEALTH

	@help(synopsis="/status", description="Show the current status.",
			see=["/encrypt", "/plain", "/stealth", "modes"])
	def _status():
		show("key %s, mode is %s" % ("available" if xmpp.key is not None
			else "not available", "plaintext" if mode == PLAIN
			else "gold" if mode == GOLD
			else "stealth" if mode == STEALTH
			else "strange"))

	@help(synopsis="/msg nick|jid message", description="Send a private "
			"message to \"nick\" or \"jid\".",
			args={	"nick":	"the nick of a user in the current "
					"room",
				"jid":	"the jid of a user, if it is either "
					"not in the current room, or if you "
					"cannot spell his name"})
	def _msg(args):
		args = parse_args(args, 1)
		nick, text = None, None
		try:
			nick = args[0]
			text = args[1].strip()
		except ValueError:
			show("syntax error")
		participants = xmpp.get_participants()
		nicks = [ participants[jid]["nick"]
				for jid in participants ]
		if not nick in nicks:
			if jid_regex.match(nick) is not None:
				xmpp.msg_send(nick, text, False)
			else:
				show("error: no such user ('%s')" % nick)
		else:
			xmpp.msg_send(nick, text, True)

	@help(synopsis="/enc text", description="Encrypt text and display the "
			"result locally. Probably only useful for debugging.",
			args={	"text": "the text to encrypt" },
			see=["/dec", "/encr"])
	def _enc(text):
		if xmpp.key is None:
			show("error: no key set")
		else:
			try:
				data = xmpp.encode(text)
				show(data)
			except Exception as e:
				show("exception: %s" % e)

	@help(synopsis="/dec text", description="Decrypt text and display the "
			"result locally. Probably only useful for debugging.",
			args={	"text": "the encrypted text you wish to "
					"decrypt"},
			see=["/enc", "/encr"])
	def _dec(text):
		if xmpp.key is None:
			show("error: no key set")
		else:
			try:
				data = xmpp.decode(text)
				show("'%s'" % data)
			except Exception as e:
				show("exception: %s" % e)

	@help(synopsis="/encr text", description="Encrypt text in the same way "
			"as /enc does, but send the result unencrypted over "
			"XMPP. Probably only useful to annoy someone.",
			args={"text": "the text you want to encrypt"},
			see=["/enc", "/dec"])
	@noshow
	def _encr(text):
		if xmpp.key is None:
			print("error: no key set")
		else:
			try:
				data = xmpp.encode(text)
				xmpp.muc_send(data, enc=False)
			except Exception as e:
				print("exception: %s" % e)

	@help(synopsis="/e text", description="Send encrypted text, exactly in "
			"the same way as in the \"encrypt\" mode, but without "
			"switching the mode.",
			args={"text": "the text you want to send"},
			see=["/encrypt"])
	@noshow
	def _e(text):
		if xmpp.key is None:
				show("error: no key set")
		else:
			try:
				xmpp.muc_send(text, enc=True)
			except Exception as e:
				show("exception: %s" % e)

	@help(synopsis="/q text", description="Send text quietly (stealth), "
			"exactly in the same way as in the \"stealth\" mode, "
			"but without switching the mode.",
			args={"text": "the text you want to send"},
			see=["/stealth"])
	@noshow
	def _q(text):
		if xmpp.key is None:
			print("error: no key set")
		else:
			try:
				xmpp.muc_send(text, stealth=True)
			except Exception as e:
				print("exception: %s" % e)

	@help(synopsis="/p text", description="Send plain text, exactly in the "
			"same way as in the \"plain\" mode, but without "
			"switching the mode.",
			args={"text": "the text you want to send"},
			see=["/plain"])
	@noshow
	def _p(text):
		xmpp.muc_send(text, enc=False)

	@help(synopsis="/es plain$encrypted", description="Send a message whose"
			" plain section is sent unmodified, but the encrypted "
			"section is replaced with a [censored] message for all "
			"normal clients. To escape the separator character "
			"(\"$\") prefix it with a \"for the cheat, set "
			"\\$21 = $33\".",
			args={"plain":	  "the plaintext portion of the "
					  "message, which will be visible to "
					  "everybody",
			      "encrypted":"the encrypted part of the message, "
					  "which will only be readable for "
					  "those with the correct key"},
			see=["/e", "/eq", "/el"])
	@noshow
	def _es(text):
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

	@help(synopsis="/eq plain$encrypted", description="Send a message whose"
			" plain section is sent unmodified, but the encrypted "
			"section is completely removed for all normal clients. "
			"To escape the separator character (\"$\") prefix it "
			"with a \"\\\", e.g. \"for the cheat, set "
			"\\$21 = $33\".",
			args={"plain":	  "the plaintext portion of the "
					  "message, which will be visible to "
					  "everybody",
			      "encrypted":"the encrypted part of the message, "
					  "which will only be visible to those "
					  "with the correct key"},
			see=["/e", "/es", "/el"])
	@noshow
	def _eq(text):
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

	@help(synopsis="/el text", description="send a message where everything"
			" starting at the first link is [encrypted]. This is "
			"the same as /es, but you do not have to insert the "
			"\"$\" manually.",
			args={"text": "the text with a link at the end"},
			see=["/e", "/es", "/eq"])
	@noshow
	def _el(text):
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

	@help(synopsis="/say text", description="Send text literally. This "
			"allows to start a message with a \"/\".",
			args={"text":"the text, wich should be sent unmodified"})
	@noshow
	def _say(text):
		send(text)

	@help(synopsis="/bell [on|off]", description="Sets or shows the usage "
			"of the terminal's bell. If enabled, the bell will ring"
			" if a message is received. Without an argument, this "
			"command shows the current setting.",
			args={	"on":	"enable the bell",
				"off":	"disable the bell"})
	def _bell(args=None):
		global enable_bell
		if args is None:
			show("bell is %s" % ("enabled" if enable_bell
				else "disabled"))
		else:
			if args == "on":
				enable_bell = True
				show("bell is now enabled")
			elif args == "off":
				enable_bell = False
				show("bell is now disabled")
			else:
				show("syntax error")

	@help(synopsis="/ls [detail]", description="List all users in the room",
			args={"detail": "if you want to see the JIDs"})
	def _ls(args=None):
		if args is None:
			participants = xmpp.get_participants()
			nicks = sorted([ participants[jid]["nick"]
					for jid in participants ])
			show("currently %d participants: %s" % (len(nicks),
					", ".join(nicks)))
		elif args == "detail":
			participants = xmpp.get_participants()
			nicks = sorted([ "  %s (%s)" %
					(participants[jid]["nick"], jid)
					for jid in participants ])
			show("currently %d participants:\n%s" %
					(len(nicks), "\n".join(nicks)))
		else:
			show("syntax error")

	@help(synopsis="/save", description="Saves the configuration. Only the "
			"default mode, the bell setting, the macros and the "
			"RegExes are saved.")
	def _save():
		save_config()

	@help(synopsis="/me text", description="send a message starting with "
			"\"/me\". This uses the current mode for transmission. "
			"You know, why this might be useful...",
			args={"text": "the text you want to say"})
	@noshow
	def _me(line):
		msg = "/me %s" % line
		send(msg)

	@help(synopsis="help text", description="Print the argument to the "
			"console")
	@noshow
	def _echo(line):
		show(line)

	running = True
	@help(synopsis="quit", description="Quit the client.")
	def _quit():
		global running
		running = False

	@help(synopsis="/rot n text", description="Use caesar cipher to encrypt"
			" text. This can be used to annoy other participants.",
			args={	"n":	"the offset",
				"text":	"the text you want to encrypt"},
			see=["/drot", "/crot"])
	def _rot(n, text):
		try:
			if n == "r":
				n = randint(1, 25)
			else:
				n = int(n)
			send(rot.rot(text, n))
		except:
			show("not a number!")

	@help(synopsis="/rotx [p|e|q] n text", description="Use caesar cipher "
			"to encrypt text. This can be used to annoy other "
			"participants. In contrast to /rot, this command sends "
			"the message with any method, ignoring the current "
			"mode",
			args={	"p":	"send this message as plaintext",
				"e":	"send this message in encrypted form",
				"q":	"send this as a stealth message",
				"n":	"the offset (choose \"r\" for random)",
				"text":	"the text you want to encrypt"},
			see=["/rot", "/drot", "/crot"])
	def _rotx(m, n, text):
		try:
			if n == "r":
				n = randint(1, 25)
			else:
				n = int(n)
			text = rot.rot(text, n)
			send_mode(m, text)
		except:
			show("not a number!")

	@help(synopsis="/drot n text", description="Decrypt a caesar cipher "
			"using a given \"n\". If you do not know the \"n\", you"
			" can try your luck with /crot.",
			args={	"n":	"the offset",
				"text":	"the text you want to decrypt"},
			see=["/rot", "/crot"])
	def _drot(n, text):
		try:
			n = int(n)
			show(rot.rot(text, 26 - n))
		except:
			show("not a number!")

	@help(synopsis="/crot lang text", description="Try to crack a caesar "
			"cipher text. If a dictionary is installed, it will "
			"use it to detect, if the decoded text contains at "
			"least one valid word in that language.",
			args={	"lang":	"the language you think this text is "
					"in",
				"text":	"the encrypted text you want to "
					"decode"},
			see=["/rot", "/drot"])
	def _crot(lang, text):
		try:
			result = rot.crackx(text, lang)
			show("rot(%d): '%s'" % (result.n, result.text))
		except Exception as e:
			show("exception: %s" % str(e))

	@help(synopsis="/cnrot n lang text", description="Try to crack a caesar"
			" cipher text and show the n-th best result.",
			args={	"n":	"you want to see this result",
				"lang":	"the language you think this text is "
					"in",
				"text":	"the encrypted text you want to "
					"decode"},
			see=["/rot", "/drot"])
	def _cnrot(n, lang, text):
		try:
			n = int(n)
		except:
			show("not a number!")
			return
		try:
			result = rot.crack(text, lang)[n]
			show("rot(%d): '%s'" % (result.n, result.text))
		except Exception as e:
			show("exception: %s" % str(e))

	@help(synopsis="/carot [lang|off]", description="Enable automatic "
			"decoding of caesar text using a given language.",
			args={	"lang":	"use this language for decoding",
				"off":	"disable automatic decoding"},
			see=["/crot", "/cnrot"])
	def _carot(arg=None):
		global decode_caesar, caesar_lang
		if arg is None:
			show("automatic caesar decoding is %s" %
					("enabled for language %s" % \
							caesar_lang if \
							decode_caesar \
							else "disabled"))
		else:
			if rot.is_supported(arg):
				decode_caesar = True
				caesar_lang = arg
				show("automatic caesar decoding is now enabled "
						"for language %s" % caesar_lang)
			elif arg == "off":
				decode_caesar = False
				show("automatic caesar decoding is now "
						"disabled")
			else:
				show("syntax error")

	@help(synopsis="/bin text", description="Encodes text into a bitstring."
			" This can be used to annoy other participants.",
			args={"text": "the text you want to encode"},
			see=["/binx"])
	def _bin(msg):
		text = "".join([ str(bin(ord(b))[2:]).zfill(8) for b in msg ])
		send(text)

	@help(synopsis="/binx [p|e|q] text", description="Encodes the text into"
			" a bitstring. This can be used to annoy other "
			"participants.",
			args={	"p":	"send this message as plaintext",
				"e":	"send this message in encrypted form",
				"q":	"send this as a stealth message",
				"text":	"the text you want to encrypt"},
			see=["/bin"])
	def _binx(m, msg):
		text = "".join([ str(bin(ord(b))[2:]).zfill(8) for b in msg ])
		send_mode(m, text)

	@help(synopsis="/hext text", description="Encodes text into a hex "
			"string. This can be used to annoy other participants.",
			args={"text": "the text you want to encode"},
			see=["/hexx"])
	def _hex(msg):
		text = ":".join([ str(hex(ord(b))[2:]).zfill(2) for b in msg ])
		send(text)

	@help(synopsis="/hexx [p|e|q] text", description="Encodes the text "
			"into a hex string. This can be used to annoy other "
			"participants.",
			args={	"p":	"send this message as plaintext",
				"e":	"send this message in encrypted form",
				"q":	"send this as a stealth message",
				"text":	"the text you want to encrypt"},
			see=["/hex"])
	def _hexx(m, msg):
		text = ":".join([ str(hex(ord(b))[2:]).zfill(2) for b in msg ])
		send_mode(m, text)

	@help(synopsis="/rhex text", description="Encodes the text "
			"with random rot(n) and the result into a hex string. "
			"This can be used to annoy other participants.",
			args={"text": "the text you want to encrypt"},
			see=["/rhexx", "/hexx", "/rotx"])
	def _rhex(msg):
		n = randint(1, 25)
		msg = rot.rot(msg, n)
		text = ":".join([ str(hex(ord(b))[2:]).zfill(2) for b in msg ])
		send(text)

	@help(synopsis="/rhexx [p|e|q] text", description="Encodes the text "
			"with random rot(n) and the result into a hex string. "
			"This can be used to annoy other participants.",
			args={	"p":	"send this message as plaintext",
				"e":	"send this message in encrypted form",
				"q":	"send this as a stealth message",
				"text":	"the text you want to encrypt"},
			see=["/rhex", "/hexx", "/rotx"])
	def _rhexx(m, msg):
		n = randint(1, 25)
		msg = rot.rot(msg, n)
		text = ":".join([ str(hex(ord(b))[2:]).zfill(2) for b in msg ])
		send_mode(m, text)

	@help(synopsis="/lulu text", description="Encodes text into the "
			"Lulu-code. This is just a binary bitstring with the "
			"1 replaced by l and 0 replaced by u. This is mainly "
			"for enjoying the voice of espeak.",
			args={"text": "the text you want to encode"},
			see=["/lulux"])
	def _lulu(msg):
		text = "".join([ str(bin(ord(b))[2:]).zfill(8) for b in msg ]) \
				.replace("1", "l").replace("0", "u")
		send(text)

	@help(synopsis="/lulux [p|e|q] text", description="Encodes the text "
			"into Lulu-code. This is just a binary bitstring with "
			"the 1 replaced by l and 0 replaced by u. This is "
			"mainly for enjoying the voice of espeak.",
			args={	"p":	"send this message as plaintext",
				"e":	"send this message in encrypted form",
				"q":	"send this as a stealth message",
				"text":	"the text you want to encrypt"},
			see=["/lulu"])
	def _lulux(m, msg):
		text = "".join([ str(bin(ord(b))[2:]).zfill(8) for b in msg ]) \
				.replace("1", "l").replace("0", "u")
		send_mode(m, text)

	@help(synopsis="/binex [p|e|q] 01 text", description="Encodes the text "
			"into a bitstring, but with a different alphabet. This "
			"can be used to annoy other participants and is mainly "
			"for enjoying the voice of espeak.",
			args={	"p":	"send this message as plaintext",
				"e":	"send this message in encrypted form",
				"q":	"send this as a stealth message",
				"01":	"use these two letters for encoding",
				"text":	"the text you want to encrypt"},
			see=["/binx"])
	def _binex(m, letters, msg):
		text = "".join([ str(bin(ord(b))[2:]).zfill(8) for b in msg ])
		letters = letters.strip()
		if letters == "r":
			letters = [ chr(i + 97) for i in range(26) ]
			shuffle(letters)
			letters = "".join(letters[0:2])
		if len(letters) != 2:
			show("syntax error")
			return
		text = text.replace("0", letters[0]).replace("1", letters[1])
		send_mode(m, text)

	add_command("help", _help)
	add_command("encrypt", _encrypt)
	add_command("plain", _plain)
	add_command("stealth", _stealth)
	add_command("status", _status)
	add_command("msg", _msg)
	add_command("enc", _enc)
	add_command("dec", _dec)
	add_command("e", _e)
	add_command("q", _q)
	add_command("p", _p)
	add_command("encr", _encr)
	add_command("es", _es)
	add_command("eq", _eq)
	add_command("el", _el)
	add_command("say", _say)
	add_command("bell", _bell)
	add_command("ls", _ls)
	add_command("save", _save)
	add_command("me", _me)
	add_command("quit", _quit)
	add_command("echo", _echo)
	add_command("rot", _rot)
	add_command("rotx", _rotx)
	add_command("drot", _drot)
	add_command("crot", _crot)
	add_command("cnrot", _cnrot)
	add_command("carot", _carot)
	add_command("bin", _bin)
	add_command("binx", _binx)
	add_command("hex", _hex)
	add_command("hexx", _hexx)
	add_command("rhex", _rhex)
	add_command("rhexx", _rhexx)
	add_command("lulu", _lulu)
	add_command("lulux", _lulux)
	add_command("binex", _binex)

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
		while running:
			if not no_colors:
				sys.stdout.write("\033%s" % INPUT_COLOR)
				sys.stdout.flush()
			line = input(prompt())
			if not line:
				continue
			msg = line.strip()
			if len(msg) == 0:
				continue
			if msg.startswith("/macro "):
				show_input(msg)
				text = msg[7:].strip()
				split = None
				try:
					split = text.index("=")
				except ValueError as e:
					try:
						split = text.index(":")
					except ValueError as e:
						show("I have no idea what to "
								"do with "
								"that...")
						continue
				cmd = text[:split].strip()
				value = text[split + 1:].strip()
				macros[cmd] = value
				show("new macro: '%s' -> '%s'" % (cmd, value))
				continue
			elif msg.startswith("/dmacro "):
				show_input(msg)
				text = msg[8:].strip()
				if text in macros:
					del macros[text]
					show("macro '%s' deleted" % text)
				else:
					show("no such macro")
				continue
			elif msg == "/macros" or msg == "/lmacros":
				show_input(msg)
				show("macros: %s" % ("none" if len(macros) == 0
						else ", ".join([ '"%s" -> "%s"'%
							(macro, macros[macro])
						for macro in macros ])))
				continue
			elif msg.startswith("/def "):
				show_input(msg)
				text = msg[5:].strip()
				split = None
				try:
					split = text.index("=")
				except ValueError as e:
					try:
						split = text.index(":")
					except ValueError as e:
						show("I have no idea what to "
								"do with "
								"that...")
						continue
				cmd = text[:split].strip()
				value = text[split + 1:].strip()
				definitions[cmd] = value
				show("new definition: '%s' -> '%s'" % (cmd,
						value))
				continue
			elif msg.startswith("/undef "):
				show_input(msg)
				text = msg[7:].strip()
				if text in definitions:
					del definitions[text]
					show("definition '%s' deleted" % text)
				else:
					show("no such definition")
				continue
			elif msg == "/defs" or msg == "/ldef":
				show_input(msg)
				show("definitions: %s" % ("none" if
						len(definitions) == 0 else
						", ".join([ '"%s" -> "%s"' %
							(definition,
							definitions[definition])
						for definition in
								definitions ])))
				continue
			elif msg.startswith("/regex "):
				show_input(msg)
				text = msg[7:].strip()
				m = re.match(r'([0-9]+)(.)"(.*)" \2 "(.*)"',
						text)
				if m is None:
					show("I have no idea what to do with "
							"that...")
					continue
				where = int(m.group(1))
				left = m.group(3)
				right = m.group(4)
				regex_program = regex_program[:where] + \
						[ (left, right) ] + \
						regex_program[where:]
				regex_default_program = \
						rp.compile(regex_program)
				show("added at %d: '%s' -> '%s'" % (where,
						left, right))
				continue
			elif msg.startswith("/dregex "):
				show_input(msg)
				try:
					text = int(msg[8:].strip())
					del regex_program[text]
					regex_default_program = \
							rp.compile(regex_program)
					show("deleted at %d" % text)
				except Exception:
					show("a (correct) number, please!")
				continue
			elif msg == "/regexes" or msg == "/lregex":
				show_input(msg)
				show("regexes: %s" % ("none" if
						len(regex_program) == 0 else
						", ".join([ '"%s" -> "%s"' %
							tuple(p) for p in
							regex_program ])))
				continue
			elif msg in macros:
				show_input(msg)
				msg = macros[msg]

			for definition in definitions:
				msg = msg.replace(definition,
						definitions[definition])
			msg = rp.run(regex_default_program, msg)

			result = execute_command(msg)
			if result is not False:
				continue
			else:
				send(msg)

	except KeyboardInterrupt: pass
	except EOFError: pass

	sys.stdout.write("\033[0m")
	sys.stdout.flush()

	xmpp.disconnect()
