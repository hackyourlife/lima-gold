# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:

import re
from collections import namedtuple

frequencies_de = [ 6.516, 1.886, 2.732, 5.076, 16.396, 1.656, 3.009, 4.577,
		6.55, 0.268, 1.417, 3.437, 2.534, 9.776, 2.594, 0.67, 0.018,
		7.003, 7.27, 6.154, 4.166, 0.846, 1.921, 0.034, 0.039, 1.134]
frequencies_de_utf = { "ä": 0.578, "ö": 0.443, "ü": 0.995, "ß": 0.307 }

frequencies_en = [ 8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
		6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095,
		5.987, 6.327, 9.056, 2.758, 0.978, 2.361, 0.15, 1.974, 0.074 ]

def merge_dicts(*dicts):
	r = {}
	for d in dicts:
		r.update(d)
	return r

def default_frequencies(lang):
	def basic_frequencies(table):
		return { chr(i + 97): table[i] / 100.0 \
				for i in range(len(table)) }

	if lang == "en":
		return basic_frequencies(frequencies_en)
	if lang == "de":
		return merge_dicts(basic_frequencies(frequencies_de),
				frequencies_de_utf)
	raise ValueError("no frequency table for language \"%s\"" % lang)

dicts = {}
def _read(path):
	with open(path) as f:
		return [ l.strip().lower() for l in f.readlines() \
				if len(l.strip()) > 0 ]

def _get_dict(lang):
	if lang == "de":
		return _read("/usr/share/dict/german")
	if lang == "en":
		return _read("/usr/share/dict/british-english")
	raise ValueError("no dict for language \"%s\"" % lang)

def get_dict(lang):
	if lang in dicts:
		return dicts[lang]
	dicts[lang] = _get_dict(lang)
	return dicts[lang]

def frequencies(text):
	return { l: text.count(l) / len(text) for l in set(text) }

def cost(text, freq):
	tf = frequencies(text)
	t = [ (tf[c] - f) ** 2 for (c, f) in freq.items() if c in tf ]
	return sum(t) / len(t)

def rot(text, n):
	def r(c, n):
		if (c < 'A' or c > 'z') or (c > 'Z' and c < 'a'): return c
		ch = chr((ord(c.upper()) - ord('A') + n) % 26 + ord('A'))
		return ch if c < 'a' else ch.lower()
	return "".join([ r(c, n) for c in text ])

Result = namedtuple("Result", ["n", "text", "error"])
def crack(text, lang):
	freq = default_frequencies(lang)
	c = { cost(rot(text, n), freq): n for n in range(0, 26) }
	candidates = sorted(c.keys())
	return [ Result(26 - c[i], rot(text, c[i]), i) for i in candidates ]

ascii_only = re.compile(r"\W")
def crackx(text, lang):
	try:
		dictionary = get_dict(lang)
	except: # try without dictionary
		return crack(text, lang)[0]
	results = crack(text, lang)
	for result in results:
		words = ascii_only.sub(" ", result.text).split(" ")
		for word in words:
			if word.lower() in dictionary:
				return result
	return results[0]
