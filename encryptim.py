import sys
from sleekxmpp.stanza import Message
from sleekxmpp.xmlstream import ElementBase, register_stanza_plugin
from sleekxmpp.plugins import BasePlugin
from sleekxmpp.plugins.base import register_plugin
from sleekxmpp.xmlstream.handler.callback import Callback
from sleekxmpp.xmlstream.matcher.xmlmask import MatchXMLMask

class ENCRYPT_IM(ElementBase):
	namespace = 'http://jabber.org/protocol/encrypted-im'
	name = 'encrypted'
	interfaces = set(['content'])
	plugin_attrib = name

class EncryptIM(BasePlugin):
	name = 'encrypt-im'
	description = 'Encrypted Stealth MUC'
	dependencies = set(['xep_0030'])
	stanza = sys.modules[__name__]

	def plugin_init(self):
		register_stanza_plugin(Message, ENCRYPT_IM)
		self.xmpp.register_handler(Callback('MUCStealthMessage',
				MatchXMLMask("<message xmlns='%s' type='groupchat'><encrypted xmlns='%s'/></message>" %
						(self.xmpp.default_ns, ENCRYPT_IM.namespace)),
				self.xmpp['xep_0045'].handle_groupchat_message))

	def session_bind(self, jid):
		self.xmpp['xep_0030'].add_feature(feature=ENCRYPT_IM.namespace)

	def plugin_end(self):
		self.xmpp['xep_0030'].del_feature(feature=ENCRYPT_IM.namespace)

def register():
	register_plugin(EncryptIM)
