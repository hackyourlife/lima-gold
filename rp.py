# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:

import re

# How?
# "normal" regex: search/replace
# "goto" regex: if replace starts with $. "if" => "$+" and "if not" => "$-"
# after the "$[+-]" the id of the next statement follows
# to use $ at the beginning in a "normal" regex, put a "\" before
class Statement(object):
	def __init__(self, regex, replace):
		self.regex_src = regex
		self.regex = re.compile(regex, re.M)
		self.replace = replace
		self.is_goto = False
		if replace[0] == "$":
			self.on_true = replace[1] == '+'
			try:
				self.bta = int(replace[2:].strip())
				self.is_goto = True
			except Exception:
				pass
		elif replace[0:1] == r"\$":
			self.replace = replace[1:]

	def __str__(self):
		return "Statement('%s', '%s')" % (self.regex_src, self.replace)

	def __repr__(self):
		return self.__str__()

def compile(data):
	return [ Statement(key, value) for (key, value) in data ]

def run(statements, text):
	if statements is None or len(statements) == 0:
		return text

	pc = 0
	t = text
	last_pc = 0
	last_t = t
	for i in range(50000): # max iterations
		statement = statements[pc]
		last_pc = pc
		last_t = t
		if statement.is_goto:
			match = statement.regex.match(t)
			if match is not None:
				if statement.on_true:
					pc = statement.bta
				else:
					pc += 1
			else:
				if statement.on_true:
					pc += 1
				else:
					pc = statement.bta
		else:
			t = statement.regex.sub(statement.replace, t)
			pc += 1
		if pc >= len(statements):
			break
		if last_pc == pc and last_t == t:
			break
	return t
