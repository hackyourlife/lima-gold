Lima Gold
=========
This client was created for the
[Lima Gold members](https://www.lima-city.de/groups/lima-gold). It supports
regular Jabber MUC conversations as well as a custom encryption and "stealth"
messages, which are invisible for regular clients.

System Requirements
-------------------
- SleekXMPP
- pycrypto
- readline
- a terminal with support for ANSI escape sequences to get all the beautiful
  colors

Configuration
-------------
Have a look at the
[xmpp.cfg.sample](https://github.com/hackyourlife/lima-gold/blob/master/xmpp.cfg.sample).

The lima gold client will look for a file called
`/etc/limagold.cfg`, `~/.limagoldrc`, `$XDG_CONFIG_HOME/limagold.conf` or
`./xmpp.cfg`. If more than one such file exists, it will load them in the given
order and override the settings accordingly. This allows a hierarchical
configuration. Additionally, the configuration can be overridden with CLI
parameters.

If no password is set in the configuration file, the client will ask
interactively. If no key is set, it will work without one, but then it cannot
send or decode encrypted messages.

Technology
----------
This client can send encrypted messages and completely invisible messages. For
encrypted messages, the content is embedded in an attribute in a HTML tag.
Invisible messages use a custom `<message>` stanza without a `body` which is is
relayed by the server but ignored by any regular client. Those invisible
messages also do not appear in the server history, which a client can request.

Archlinux-Package
-----------------
To install lima-gold as a package on Archlinux, run `makepkg` and install the
package. You will have to create a config file in a well-known location and
configure the logfile config option to an absolute path.
