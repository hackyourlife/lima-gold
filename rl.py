# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:

from ctypes import cdll, cast, c_int, c_char_p, c_void_p
from ctypes.util import find_library
import readline as r
import sys

rl = cdll.LoadLibrary("libreadline.so")

rl_readline_state = c_int.in_dll(rl, "rl_readline_state")
rl_point = c_int.in_dll(rl, "rl_point")
rl_end = c_int.in_dll(rl, "rl_end")

rl_replace_line = rl.rl_replace_line
rl_replace_line.argtypes = [ c_char_p, c_int ]
rl_save_prompt = rl.rl_save_prompt
rl_restore_prompt = rl.rl_restore_prompt
rl_copy_text = rl.rl_copy_text
rl_copy_text.argtypes = [ c_int, c_int ]
rl_copy_text.restype = c_void_p
rl_redisplay = rl.rl_redisplay
_readline = rl.readline
_readline.argtypes = [ c_char_p ]
_readline.restype = c_void_p

RL_STATE_DONE = 0x1000000

stdlibc = cdll.LoadLibrary(find_library("c"))
free = stdlibc.free
free.argtypes = [ c_void_p ]

def get_and_free(voidp):
	p = cast(voidp, c_char_p)
	text = p.value.decode()
	free(voidp)
	return text

def echo(text, prompt_prefix=None):
	readline_active = (rl_readline_state.value & RL_STATE_DONE) == 0

	if readline_active:
		saved_point = rl_point.value
		saved_line = r.get_line_buffer()
		rl_save_prompt()
		rl_replace_line(c_char_p(b""), 0)
		rl_redisplay()

	print(text)

	if readline_active:
		if prompt_prefix is not None:
			sys.stdout.write(prompt_prefix)
			sys.stdout.flush()
		rl_restore_prompt()
		rl_replace_line(c_char_p(saved_line.encode()), 0)
		rl_point.value = saved_point
		rl_redisplay()

def readline(prompt):
	data = _readline(c_char_p(prompt.encode()))
	if data is None:
		raise EOFError()
	return get_and_free(data)
