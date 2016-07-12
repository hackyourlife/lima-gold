#!/bin/python
# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:

import sys
import configparser
import logging
from client import Client

from Crypto.Cipher import AES
import base64

logger = logging.getLogger(__name__)

def decode(key, msg):
	raw = base64.b64decode(msg)
	iv = raw[0:AES.block_size]
	msg = raw[AES.block_size:]
	aes = AES.new(key, AES.MODE_CBC, iv)
	data = aes.decrypt(msg)
	print("key:  %s" % " ".join([ "%02x" % x for x in key ]))
	print("iv:   %s" % " ".join([ "%02x" % x for x in iv ]))
	print("msg:  %s" % " ".join([ "%02x" % x for x in msg ]))
	print("data: %s" % " ".join([ "%02x" % x for x in data ]))
	return data[:-data[-1]]

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

	xmpp = Client(jid, password, room, nick, key)

	operation = sys.argv[1]
	data = sys.argv[2]
	if operation == '-e':
		print(xmpp.encode(data))
	elif operation == '-d':
		print(xmpp.decode(data))
	elif operation == '-h':
		result = decode(xmpp.key, data)
		print(result)
