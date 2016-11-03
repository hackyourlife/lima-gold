#!/bin/python
# -*- coding: utf-8 -*-
# vim: set ts=8 sts=8 sw=8 tw=80 noet cc=80 :

import os.path
import json
import random

QUOTES = {}

def init(config):
	if not config.has_section("random_quote"):
		return None
	for option in config.options("random_quote"):
		try:
			config_path = json.loads(config.get("random_quote",
				option))
		except:
			print("Invalid json in config: " +
					config.get("random_quote", option))
		if not isinstance(config_path, list):
			config_path = [config_path]
		qs = []
		for p in config_path:
			p = os.path.expanduser(p)
			if isinstance(p, str) and os.path.isfile(p):
				qs.extend([l.strip() for l in
					open(p).readlines()])
			else:
				print(">> 404 No such file: " + p)
		if len(qs) > 0:
			QUOTES[option] = qs

def get_lists():
	return list(QUOTES.keys())

def random_quote(lst=None):
	if lst == None:
		lst = random.choice(list(QUOTES.keys()))
	elif lst not in QUOTES:
		return None
	return random.choice(QUOTES[lst])
