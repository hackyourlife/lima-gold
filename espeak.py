# -*- coding: utf-8 -*-
# vim:set ts=8 sts=8 sw=8 tw=80 noet cc=80:

from ctypes import cdll, c_int, c_char_p, c_wchar_p, c_uint, c_long,  \
		c_void_p, c_short, POINTER, Structure, Union, CFUNCTYPE
		
from ctypes.util import find_library
from queue import Queue
from threading import Thread

try:
	espeak = cdll.LoadLibrary(find_library("espeak"))
except:
	espeak = None

def func(name, rtype, args=[]):
	if espeak is None:
		return None
	f = getattr(espeak, name)
	f.restype = rtype
	f.argtypes = args
	return f

RATE_MINIMUM		= 80
RATE_MAXIMUM		= 450
RATE_NORMAL		= 175

EVENT_LIST_TERMINATED	= 0 # Retrieval mode: terminates the event list.
EVENT_WORD		= 1 # Start of word
EVENT_SENTENCE		= 2 # Start of sentence
EVENT_MARK		= 3 # Mark
EVENT_PLAY		= 4 # Audio element
EVENT_END		= 5 # End of sentence or clause
EVENT_MSG_TERMINATED	= 6 # End of message
EVENT_PHONEME		= 7 # Phoneme, if enabled in espeak_Initialize()
EVENT_SAMPLERATE	= 8 # internal use, set sample rate

AUDIO_OUTPUT_PLAYBACK	= 0
AUDIO_OUTPUT_RETRIEVAL	= 1
AUDIO_OUTPUT_SYNCHRONOUS = 2
AUDIO_OUTPUT_SYNCH_PLAYBACK = 3

POS_CHARACTER		= 1
POS_WORD		= 2
POS_SENTENCE		= 3

CHARS_AUTO		= 0
CHARS_UTF8		= 1
CHARS_8BIT		= 2
CHARS_WCHAR		= 3
CHARS_16BIT		= 4

SSML			= 0x10
PHONEMES		= 0x100
ENDPAUSE		= 0x1000
KEEP_NAMEDATA		= 0x2000

SILENCE			= 0
RATE			= 1
VOLUME			= 2
PITCH			= 3
RANGE			= 4
PUNCTUATION		= 5
CAPITALS		= 6
WORDGAP			= 7
OPTIONS			= 8
INTONATION		= 9

RESERVED1		= 10
RESERVED2		= 11
EMPHASIS		= 12
LINELENGTH		= 13
VOICETYPE		= 14
N_SPEECH_PARAM		= 15

PUNCT_NONE		= 0
PUNCT_ALL		= 1
PUNCT_SOME		= 2

EE_OK			= 0
EE_INTERNAL_ERROR	= -1
EE_BUFFER_FULL		= 1
EE_NOT_FOUND		= 2

class EspeakNotFound(Exception):
	pass
class BufferFull(Exception):
	pass
class NotFound(Exception):
	pass
class InternalError(Exception):
	pass

class numberORname(Union):
	_fields_ = [
		('number', c_int),
		('name', c_char_p)
		]

class EVENT(Structure):
	_fields_ = [
		('type', c_int),
		('unique_identifier', c_uint),
		('text_position', c_int),
		('length', c_int),
		('audio_position', c_int),
		('sample', c_int),
		('user_data', c_void_p),
		('id', numberORname)
		]

callback_t = CFUNCTYPE(c_int, POINTER(c_short), c_int, POINTER(EVENT))

# C API functions
_Initialize = func("espeak_Initialize", c_int, \
		[ c_int, c_int, c_char_p, c_int ])
_Terminate = func("espeak_Terminate", c_int)
_SetSynthCallback = func("espeak_SetSynthCallback", None, [ callback_t ])
_Synth = func("espeak_Synth", c_int, \
		[ c_wchar_p, c_long, c_uint, c_int, c_uint, c_uint,
			POINTER(c_uint), c_void_p ])
_SetParameter = func("espeak_SetParameter", c_int, [ c_int, c_int, c_int ])
_GetParameter = func("espeak_GetParameter", c_int, [ c_int, c_int ])
_SetVoiceByName = func("espeak_SetVoiceByName", c_int, [ c_char_p ])
_Cancel = func("espeak_Cancel", c_int)
_Synchronize = func("espeak_Synchronize", c_int)

# Python API
queue = Queue()
running = True
def _async():
	def worker():
		while running:
			text = queue.get()
			if len(text.strip()) == 0:
				continue
			queue.task_done()
			synth(text)
			synchronize()

	running = True
	t = Thread(target=worker)
	t.daemon = True
	t.start()

def say(text):
	queue.put(text)

def initialize(output=AUDIO_OUTPUT_PLAYBACK, buffer_length=100, path=None,
		option=0):
	if espeak is None:
		raise EspeakNotFound()
	path = None if path is None else c_char_p(path.encode("ascii"))
	result = _Initialize(output, buffer_length, path, option)
	if result == EE_INTERNAL_ERROR:
		raise InternalError()
	_async()
	return result

def terminate():
	global running
	running = False
	say("") # wake up worker

	result = _Terminate()
	if result == EE_OK:
		return
	elif result == EE_INTERNAL_ERROR:
		raise InternalError()
	else:
		raise Exception("unknown result value")

def set_parameter(parameter, value, relative):
	result = _SetParameter(parameter, value, relative)
	if result == EE_OK:
		return
	elif result == EE_BUFFER_FULL:
		raise BufferFull()
	elif result == EE_INTERNAL_ERROR:
		raise InternalError()
	else:
		raise Exception("unknown result value")

def get_parameter(parameter, current=0):
	return _GetParameter(parameter, current)

def set_voice(name):
	set_voice_by_name(name)

def set_voice_by_name(name):
	name = c_char_p(name.encode("utf-8"))
	result = _SetVoiceByName(name)
	if result == EE_OK:
		return
	elif result == EE_BUFFER_FULL:
		raise BufferFull()
	elif result == EE_INTERNAL_ERROR:
		raise InternalError()
	else:
		raise Exception("unknown result value")

synth_callback = None
def set_synth_callback(callback):
	global synth_callback
	synth_callback = callback_t(callback)
	_SetSynthCallback(synth_callback)

def synth(text, size=None, position=0, position_type=POS_CHARACTER,
		end_position=0, flags=CHARS_WCHAR, unique_identifier=None,
		user_data=None):
	size = len(text) * 20 if size is None else size
	result = _Synth(c_wchar_p(text), size, position, position_type,
			end_position, flags, unique_identifier, user_data)
	if result == EE_OK:
		return
	elif result == EE_BUFFER_FULL:
		raise BufferFull()
	elif result == EE_INTERNAL_ERROR:
		raise InternalError()
	else:
		raise Exception("unknown result value")

def cancel():
	result = _Cancel()
	if result == EE_OK:
		return
	elif result == EE_INTERNAL_ERROR:
		raise InternalError()
	else:
		raise Exception("unknown result value")

def synchronize():
	result = _Synchronize()
	if result == EE_OK:
		return
	elif result == EE_INTERNAL_ERROR:
		raise InternalError()
	else:
		raise Exception("unknown result value")
