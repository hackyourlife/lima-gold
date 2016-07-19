# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:

def noshow(func):
	func.noshow = True
	return func

def help(**args):
	def decorator(func):
		func.help = args
		return func
	return decorator

def get_help(func):
	if hasattr(func, "help"):
		return func.help
	return None
