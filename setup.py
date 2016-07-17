#!/bin/python
# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:

from distutils.core import setup

setup(
	name             = "lima-gold",
	version          = '1.0',
	description      = 'Terminal based Jabber MUC client',
	long_description = 'A terminal based Jabber MUC client with support for'
	                   ' encrypted and invisible messages',
	author           = 'root',
	url              = 'https://github.com/hackyourlife/lima-gold',
	platforms        = [ 'any' ],
	packages         = [ '.' ],
	requires         = [ 'sleekxmpp', 'pycrypto' ],
)
