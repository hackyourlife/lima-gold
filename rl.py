# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:

from ctypes import cdll, cast, c_int, c_char_p, c_void_p, CFUNCTYPE
from ctypes.util import find_library
import readline as r
import sys

rl = cdll.LoadLibrary(find_library("readline"))

rl_readline_state = c_int.in_dll(rl, "rl_readline_state")
rl_point = c_int.in_dll(rl, "rl_point")
rl_done = c_int.in_dll(rl, "rl_done")

RL_CALLBACK = CFUNCTYPE(c_int, c_int, c_int)

rl_set_prompt = rl.rl_set_prompt
rl_set_prompt.argtypes = [ c_char_p ]
rl_replace_line = rl.rl_replace_line
rl_replace_line.argtypes = [ c_char_p, c_int ]
rl_save_prompt = rl.rl_save_prompt
rl_restore_prompt = rl.rl_restore_prompt
rl_copy_text = rl.rl_copy_text
rl_copy_text.argtypes = [ c_int, c_int ]
rl_copy_text.restype = c_void_p
rl_redisplay = rl.rl_redisplay
rl_bind_key = rl.rl_bind_key
rl_bind_key.argtypes = [ c_int, RL_CALLBACK ]
_readline = rl.readline
_readline.argtypes = [ c_char_p ]
_readline.restype = c_void_p

RL_STATE_DONE = 0x1000000

control_character_mask = 0x1f
CTRL = lambda c: ord(c) & control_character_mask
RETURN = CTRL("M")
ESC = CTRL("[")

stdlibc = cdll.LoadLibrary(find_library("c"))
free = stdlibc.free
free.argtypes = [ c_void_p ]

delete_input = False

def handle_return(x, y):
	if not delete_input:
		rl_done.value = 1
		print()
		return 0
	line = r.get_line_buffer()
	if line is not None and len(line) > 0:
		r.add_history(line)

	rl_set_prompt(c_char_p(b""))
	rl_replace_line(c_char_p(b""), 0)
	rl_redisplay()
	rl_replace_line(c_char_p(line.encode()), 1)
	rl_done.value = 1
	return 0

def set_delete_input(value=True):
	global delete_input
	delete_input = value

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

_enter_handler = RL_CALLBACK(handle_return)
def init():
	rl_bind_key(RETURN, _enter_handler)
	pass

r.set_startup_hook(init)
