# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:
"""
Functions to encode and decode morse code
"""

import re
strip = re.compile("\s{2,}")

CHARS_TO_MORSE = {"A": "·−", "B": "−···", "C": "−·−·", "D": "−··", "E": "·",
		"F": "··−·", "G": "−−·", "H": "····", "I": "··", "J": "·−−−",
		"K": "−·−", "L": "·−··", "M": "−−", "N": "−·", "O": "−−−",
		"P": "·−−·", "Q": "−−·−", "R": "·−·", "S": "···", "T": "−",
		"U": "··−", "V": "···−", "W": "·−−", "X": "−··−", "Y": "−·−−",
		"Z": "−−··", "1": "·−−−−", "2": "··−−−", "3": "···−−",
		"4": "····−", "5": "·····", "6": "−····", "7": "−−···",
		"8": "−−−··", "9": "−−−−·", "0": "−−−−−", "À": "·−−·−",
		"Ä": "·−·−", "È": "·−··−", "É": "··−··", "Ö": "−−−·",
		"Ü": "··−−", "ß": "···−−··", "CH": "−−−−", "Ñ": "−−·−−",
		".": "·−·−·−", ",": "−−··−−", ":": "−−−···", ";": "−·−·−·",
		"?": "··−−··", "-": "−····−", "_": "··−−·−", "(": "−·−−·",
		")": "−·−−·−", "'": "·−−−−·", "=": "−···−", "+": "·−·−·",
		"/": "−··−·", "@": "·−−·−·", "!": "−·−·−−", '"': "·−··−·",
		"$": "···−··−"}

MORSE_TO_CHARS = {CHARS_TO_MORSE[key]: key for key in CHARS_TO_MORSE}

def encode(msg):
	"""
	Decode a string to morse code
	"""
	text = []
	for letter in msg.upper():
		if letter in CHARS_TO_MORSE:
			text.append(CHARS_TO_MORSE[letter])
		elif letter == " ":
			text.append("")
		else:
			text.append(CHARS_TO_MORSE["?"])
	return " ".join(text)

def decode(msg):
	"""
	Decode a string containing morse code
	"""
	tmp = []
	for letter in msg.replace(".", "·").replace("-", "−").split(" "):
		if len(letter) == 0:
			tmp.append(" ")
		elif letter in MORSE_TO_CHARS:
			tmp.append(MORSE_TO_CHARS[letter])
	return strip.sub(" ", "".join(tmp).lower().strip())

def valid(msg):
	"""
	Check if a string contains morse code
	"""
	msg = strip.sub("  ", msg.strip()) # 2 or more spaces -> 2 spaces
	tmp = decode(msg)
	if len(msg.split(" ")) == len(tmp):
		return True
	return False
