#!/usr/bin/env python
#
# faux-gnome-screensaver.py
# This file is part of faux-gnome-screensaver
#
# Copyright (C) 2012-2013 Jeffery To <jeffery.to@gmail.com>
# https://github.com/jefferyto/faux-gnome-screensaver
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from gi.repository import GLib, GObject, Gio
import ctypes
import datetime
import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
import logging
import optparse
import os
import re
import signal
import subprocess
import sys
import time

LOG = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(name)s %(levelname)s: %(message)s'


class XScreenSaverManager(GObject.GObject):
	__gsignals__ = {
		'active-changed': (GObject.SignalFlags.RUN_LAST, None, (bool,)),
		'timeout-changed': (GObject.SignalFlags.RUN_LAST, None, (int,))
	}

	XSS = 'xscreensaver'
	XSS_COMMAND = 'xscreensaver-command'
	XSS_OPTIONS = '~/.xscreensaver'

	XSET = 'xset'

	DEFAULT_TIMEOUT = 600 # in seconds

	DATETIME_FORMAT = '%a %b %d %H:%M:%S %Y'
	TIMEOUT_FORMAT = '%H:%M:%S'

	def __init__(self, no_dpms=False):
		self._screensaver = None
		self._active = None
		self._active_since = None
		self._locked = None
		self._watcher = None
		self._watcher_read_buf = None
		self._watcher_id = None
		self._options_path = None
		self._options_gfile = None
		self._options_monitor = None
		self._options_monitor_id = None
		self._manage_dpms = not no_dpms
		self._inhibit_id = None

		super(XScreenSaverManager, self).__init__()

	def activate(self):
		LOG.debug("Starting screensaver")
		try:
			self._screensaver = subprocess.Popen([self.XSS, '-nosplash'])
		except OSError as err:
			LOG.error("Cannot start screensaver: %s", err)
			raise
		time.sleep(1)

		self._active = False
		self._active_since = datetime.datetime.now()
		self._locked = False
		match = re.search(r"screen (\S+) since ([^\(]+)", self._do_command('time'))
		if match:
			state, date_str = match.groups()
			self._active = state != 'non-blanked'
			self._active_since = datetime.datetime.strptime(date_str.strip(), self.DATETIME_FORMAT)
			self._locked = state == 'locked'

		LOG.debug("Starting watcher")
		try:
			self._watcher = subprocess.Popen([self.XSS_COMMAND, '-watch'], stdout=subprocess.PIPE)
		except OSError as err:
			LOG.error("Cannot start watcher: %s", err)
			raise
		self._watcher_read_buf = []
		self._watcher_id = GLib.io_add_watch(self._watcher.stdout, GLib.IO_IN, self._read_from_watcher)

		self._timeout = -1
		self._options_path = os.path.expanduser(self.XSS_OPTIONS)

		self._read_timeout(None, init=True)

		self._options_gfile = Gio.file_new_for_path(self._options_path)
		self._options_monitor = self._options_gfile.monitor_file(Gio.FileMonitorFlags.NONE, None)
		self._options_monitor_id = self._options_monitor.connect('changed', lambda m, f, g, e: self._read_timeout(e))

	def deactivate(self):
		if self._inhibit_id is not None:
			GLib.source_remove(self._inhibit_id)

		if self._options_monitor:
			self._options_monitor.disconnect(self._options_monitor_id)
			self._options_monitor.cancel()

		if self._watcher_id is not None:
			GLib.source_remove(self._watcher_id)

		if self._watcher:
			LOG.debug("Ending watcher")
			self._watcher.terminate()

		if self._screensaver and self._screensaver.poll() is None:
			LOG.debug("Ending screensaver")
			self._do_command('exit')
			time.sleep(1)

		self._screensaver = None
		self._active = None
		self._active_since = None
		self._locked = None
		self._watcher = None
		self._watcher_read_buf = None
		self._watcher_id = None
		self._timeout = None
		self._options_path = None
		self._options_gfile = None
		self._options_monitor = None
		self._options_monitor_id = None
		self._inhibit_id = None

	def _do_command(self, cmd):
		LOG.debug("Calling %s -%s", self.XSS_COMMAND, cmd)
		try:
			process = subprocess.Popen([self.XSS_COMMAND, '-' + cmd], stdout=subprocess.PIPE)
			output = process.communicate()[0].strip()
			retcode = process.returncode
			if retcode < 0:
				LOG.error("%s was terminated by signal %d", self.XSS_COMMAND, -retcode)
				output = None
			else:
				LOG.debug("  output (exit: %d): %s", retcode, output)
		except OSError as err:
			LOG.error("Cannot call %s: %s", self.XSS_COMMAND, err)
			output = None

		return output

	def _read_from_watcher(self, source, condition):
		c = source.read(1)
		if c != '\n':
			self._watcher_read_buf.append(c)
		else:
			event = ''.join(self._watcher_read_buf)
			self._watcher_read_buf = []
			state, rest = event.split(None, 1)
			if state == 'BLANK' or state == 'LOCK' or state == 'UNBLANK':
				active = state != 'UNBLANK'
				since = datetime.datetime.strptime(rest.strip(), self.DATETIME_FORMAT)
				self._locked = state == 'LOCK'
				LOG.debug("Screensaver state changed to %s at %s", state, since)
				if active != self._active:
					self._active = active
					self._active_since = since
					self.emit('active-changed', active)

		return True

	def _read_timeout(self, event_type, init=False):
		if event_type == Gio.FileMonitorEvent.CHANGES_DONE_HINT or event_type == Gio.FileMonitorEvent.DELETED or init:
			timeout = self.DEFAULT_TIMEOUT

			if event_type == Gio.FileMonitorEvent.CHANGES_DONE_HINT or init:
				if init:
					LOG.debug("Attempting to read from %s", self._options_path)
				else:
					LOG.debug("%s changed, attempting to read", self._options_path)
				try:
					f = open(self._options_path, 'r')
					for line in f:
						a = line.strip().split()
						if len(a) == 2 and a[0] == 'timeout:':
							LOG.debug("  found timeout: %s", a[1])
							# 12 hours seems to be the max timeout, so this should be okay
							try:
								dt = datetime.datetime.strptime(a[1], self.TIMEOUT_FORMAT)
								timeout = dt.second + (dt.minute * 60) + (dt.hour * 3600)
								LOG.debug("Timeout was %d seconds, now %d seconds", self._timeout, timeout)
							except ValueError as err:
								LOG.debug("  cannot parse timeout: %s", err)
								LOG.debug("Resetting timeout to default (%d seconds)", timeout)
							break
				except IOError as err:
					LOG.debug("  failed: %s", err)
					LOG.debug("Resetting timeout to default (%d seconds)", timeout)
			else:
				LOG.debug("%s deleted, resetting timeout to default (%d seconds)", self._options_path, timeout)

			if timeout != self._timeout:
				self._timeout = timeout
				if self._inhibit_id is not None:
					self.inhibit()
				self.emit('timeout-changed', timeout)

	def _set_dpms(self, enable):
		if self._manage_dpms:
			cmd = '+dpms' if enable else '-dpms'
			LOG.debug("Calling %s %s", self.XSET, cmd)
			try:
				output = subprocess.check_output([self.XSET, cmd], stderr=subprocess.STDOUT)
				if output:
					LOG.error("%s returned with output: %s", self.XSET, output)
				else:
					LOG.debug("  exited normally")
			except subprocess.CalledProcessError as err:
				LOG.error("%s returned non-zero exit status %d: %s", self.XSET, err.returncode, err.output)
			except OSError as err:
				LOG.error("Cannot call %s: %s", self.XSET, err)

	@property
	def active(self):
		return self._active

	@active.setter
	def active(self, value):
		if value != self._active:
			if value:
				LOG.debug("Screensaver is inactive, activating")
				cmd = 'activate'
			else:
				LOG.debug("Screensaver is active, deactivating")
				cmd = 'deactivate'
			self._do_command(cmd)
		else:
			if value:
				LOG.debug("Screensaver is already active")
			else:
				LOG.debug("Screensaver is already inactive")

	@property
	def active_time(self):
		seconds = 0
		if self._active:
			delta = datetime.datetime.now() - self._active_since
			seconds = delta.seconds + (delta.days * 3600)
		return seconds

	@property
	def timeout(self):
		return self._timeout

	def lock(self):
		if not self._locked:
			LOG.debug("Locking")
			self._do_command('lock')
		else:
			LOG.debug("Already locked")

	def simulate_user_activity(self):
		LOG.debug("Simulating user activity")
		self._do_command('deactivate')

	def inhibit(self):
		interval = max(20, self._timeout - 10)
		LOG.debug("Inhibiting screensaver every %d seconds", interval)
		if self._inhibit_id is not None:
			GLib.source_remove(self._inhibit_id)
		self._do_inhibit()
		self._inhibit_id = GLib.timeout_add(interval * 1000, self._do_inhibit)

	def uninhibit(self):
		LOG.debug("Uninhibiting screensaver")
		if self._inhibit_id is not None:
			self._set_dpms(True)
			GLib.source_remove(self._inhibit_id)
			self._inhibit_id = None

	def _do_inhibit(self):
		if not self._locked:
			LOG.debug("Inhibiting")
			self._do_command('deactivate')
			self._set_dpms(False)
		else:
			LOG.debug("Screensaver is locked, skipping inhibit")
		return True


class FauxGnomeScreensaverDBusService(dbus.service.Object):
	GS_SERVICE = 'org.gnome.ScreenSaver'
	GS_PATH = '/org/gnome/ScreenSaver'

	def __init__(self, owner):
		self._owner = owner

		LOG.debug("Adding %s dbus service", self.GS_SERVICE)
		bus = dbus.SessionBus()
		bus_name = dbus.service.BusName(name=self.GS_SERVICE, bus=bus)
		super(FauxGnomeScreensaverDBusService, self).__init__(bus_name, self.GS_PATH)

	def uninit(self):
		LOG.debug("Removing %s dbus service", self.GS_SERVICE)
		self._owner = None

	def _log_method(self, method, sender, in_args=None):
		LOG.debug("Received %s method call to org.gnome.ScreenSaver from %s", method, sender or "unknown sender")
		if in_args:
			LOG.debug("  with arguments: %s", in_args)

	def _log_method_return(self, method, value):
		LOG.debug("Returning %s for %s method call", value, method)

	def _log_signal(self, signal, out_args=None):
		LOG.debug("Emitting %s signal from org.gnome.ScreenSaver", signal)
		if out_args:
			LOG.debug("  with values: %s", out_args)

	@dbus.service.method(dbus_interface='org.gnome.ScreenSaver', sender_keyword='sender')
	def Quit(self, sender=None):
		self._log_method('Quit', sender)
		self._owner.emit('quit')

	@dbus.service.method(dbus_interface='org.gnome.ScreenSaver', sender_keyword='sender')
	def Lock(self, sender=None):
		self._log_method('Lock', sender)
		self._owner.emit('lock')

	@dbus.service.method(dbus_interface='org.gnome.ScreenSaver', sender_keyword='sender')
	def SimulateUserActivity(self, sender=None):
		self._log_method('SimulateUserActivity', sender)
		self._owner.emit('simulate-user-activity')

	@dbus.service.method(dbus_interface='org.gnome.ScreenSaver', in_signature='b', sender_keyword='sender')
	def SetActive(self, value, sender=None):
		self._log_method('SetActive', sender, (value,))
		self._owner.emit('set-active', value)

	@dbus.service.method(dbus_interface='org.gnome.ScreenSaver', out_signature='b', sender_keyword='sender')
	def GetActive(self, sender=None):
		self._log_method('GetActive', sender)
		active = self._owner.emit('get-active')
		self._log_method_return('GetActive', active)
		return active

	@dbus.service.method(dbus_interface='org.gnome.ScreenSaver', out_signature='u', sender_keyword='sender')
	def GetActiveTime(self, sender=None):
		self._log_method('GetActiveTime', sender)
		seconds = self._owner.emit('get-active-time')
		self._log_method_return('GetActiveTime', seconds)
		return seconds

	@dbus.service.method(dbus_interface='org.gnome.ScreenSaver', in_signature='sss', sender_keyword='sender')
	def ShowMessage(self, summary, body, icon, sender=None):
		self._log_method('ShowMessage', sender, (summary, body, icon))
		# FIXME
		LOG.warning("ShowMessage not implemented: sender=%s summary=%s body=%s icon=%s", sender, summary, body, icon)

	@dbus.service.signal(dbus_interface='org.gnome.ScreenSaver', signature='b')
	def ActiveChanged(self, new_value):
		self._log_signal('ActiveChanged', (new_value,))


class FauxGnomeScreensaverService(GObject.GObject):
	__gsignals__ = {
		'quit': (GObject.SignalFlags.RUN_LAST, None, ()),
		'lock': (GObject.SignalFlags.RUN_LAST, None, ()),
		'simulate-user-activity': (GObject.SignalFlags.RUN_LAST, None, ()),
		'set-active': (GObject.SignalFlags.RUN_LAST, None, (bool,)),
		'get-active': (GObject.SignalFlags.RUN_LAST, bool, ()),
		'get-active-time': (GObject.SignalFlags.RUN_LAST, int, ())
	}

	def __init__(self):
		self._service = None

		super(FauxGnomeScreensaverService, self).__init__()

	def activate(self):
		self._service = FauxGnomeScreensaverDBusService(self)

	def deactivate(self):
		if self._service:
			self._service.uninit()
			self._service = None

	def active_changed(self, active):
		if self._service:
			self._service.ActiveChanged(active)


class GnomeSessionManagerListener(GObject.GObject):
	__gsignals__ = {
		'inhibited-changed': (GObject.SignalFlags.RUN_LAST, None, (bool,))
	}

	GSM_SERVICE = 'org.gnome.SessionManager'
	GSM_PATH = '/org/gnome/SessionManager'
	GSM_INTERFACE = 'org.gnome.SessionManager'
	GSM_INHIBITOR_FLAG_IDLE = 8

	def __init__(self):
		self._iface = None
		self._inhibited = None

		super(GnomeSessionManagerListener, self).__init__()

	def activate(self):
		bus = dbus.SessionBus()
		proxy = bus.get_object(self.GSM_SERVICE, self.GSM_PATH)
		iface = dbus.Interface(proxy, dbus_interface=self.GSM_INTERFACE)

		self._iface = iface
		self._check_inhibited()

		LOG.debug("Listening for InhibitorAdded and InhibitorRemoved from %s", self.GSM_INTERFACE)
		iface.connect_to_signal('InhibitorAdded', self._inhibitor_added)
		iface.connect_to_signal('InhibitorRemoved', self._inhibitor_removed)

	def deactivate(self):
		LOG.debug("Disconnecting from %s", self.GSM_INTERFACE)
		self._iface = None
		self._inhibited = None

	def _inhibitor_added(self, inhibitor_id):
		LOG.debug("Received InhibitorAdded signal from %s", self.GSM_INTERFACE)
		self._check_inhibited()

	def _inhibitor_removed(self, inhibitor_id):
		LOG.debug("Received InhibitorRemoved signal from %s", self.GSM_INTERFACE)
		self._check_inhibited()

	def _check_inhibited(self):
		inhibited = self._iface.IsInhibited(self.GSM_INHIBITOR_FLAG_IDLE)
		LOG.debug("%s is %s", self.GSM_INTERFACE, 'idle inhibited' if inhibited else 'not idle inhibited')
		if inhibited != self._inhibited:
			self._inhibited = inhibited
			self.emit('inhibited-changed', inhibited)


class ConsoleKitListener(GObject.GObject):
	__gsignals__ = {
		'lock': (GObject.SignalFlags.RUN_LAST, None, ()),
		'unlock': (GObject.SignalFlags.RUN_LAST, None, ()),
		'is-active': (GObject.SignalFlags.RUN_LAST, None, ())
	}

	CK_SERVICE = 'org.freedesktop.ConsoleKit'
	CK_PATH = '/org/freedesktop/ConsoleKit'
	CK_INTERFACE = 'org.freedesktop.ConsoleKit'

	CK_MANAGER_PATH = CK_PATH + '/Manager'
	CK_MANAGER_INTERFACE = CK_INTERFACE + '.Manager'

	CK_SESSION_PATH = CK_PATH + '/Session'
	CK_SESSION_INTERFACE = CK_INTERFACE + '.Session'

	def __init__(self):
		self._ssid = None
		self._matches = []

		super(ConsoleKitListener, self).__init__()

	def activate(self):
		bus = dbus.SystemBus()

		LOG.debug("Getting current ConsoleKit session id")
		try:
			manager = bus.get_object(self.CK_SERVICE, self.CK_MANAGER_PATH)
			ssid = manager.GetCurrentSession(dbus_interface=self.CK_MANAGER_INTERFACE)
		except dbus.exceptions.DBusException as err:
			LOG.warning("Cannot get current ConsoleKit session id: %s", err)
			ssid = None

		if ssid is not None:
			self._ssid = ssid

			LOG.debug("Listening for Lock, Unlock and ActiveChanged from %s", self.CK_SESSION_INTERFACE)
			# sender path is the session id
			for s, h in [
						('Lock', self._lock),
						('Unlock', self._unlock),
						('ActiveChanged', self._active_changed)
					]:
				self._matches.append(bus.add_signal_receiver(h, signal_name=s, dbus_interface=self.CK_SESSION_INTERFACE, path_keyword='path'))

	def deactivate(self):
		LOG.debug("Disconnecting from %s", self.CK_SESSION_INTERFACE)

		for m in self._matches:
			m.remove()

		self._ssid = None
		self._matches = []

	def _lock(self, path=None):
		if path == self._ssid:
			LOG.debug("Received Lock signal from %s", self.CK_SESSION_INTERFACE)
			self.emit('lock')

	def _unlock(self, path=None):
		if path == self._ssid:
			LOG.debug("Received Unlock signal from %s", self.CK_SESSION_INTERFACE)
			self.emit('unlock')

	def _active_changed(self, is_active, path=None):
		if path == self._ssid:
			LOG.debug("Received ActiveChanged signal from %s, is_active=%s", self.CK_SESSION_INTERFACE, is_active)
			if is_active:
				self.emit('is-active')


class GSettingsManager(GObject.GObject):
	SCHEMA_SCREENSAVER = 'org.gnome.desktop.screensaver'
	SCHEMA_SESSION = 'org.gnome.desktop.session'
	SCHEMA_POWER = 'org.gnome.settings-daemon.plugins.power'

	SETTINGS = {
		'idle-activation-enabled': {
			'schema': SCHEMA_SCREENSAVER,
			'type': 'boolean',
			'clamp': False
		},
		'idle-delay': {
			'schema': SCHEMA_SESSION,
			'type': 'uint',
			'clamp': 0
		},
		'sleep-display-ac': {
			'schema': SCHEMA_POWER,
			'type': 'int',
			'clamp': 0
		},
		'sleep-display-battery': {
			'schema': SCHEMA_POWER,
			'type': 'int',
			'clamp': 0
		}
	}

	def __init__(self):
		self._gsettings = None
		self._saved = None

		super(GSettingsManager, self).__init__()

	def activate(self):
		self._gsettings = {}
		for key, info in self.SETTINGS.iteritems():
			schema = info['schema']
			if schema not in self._gsettings:
				self._gsettings[schema] = Gio.Settings(schema)

		self._saved = {}
		for key, info in self.SETTINGS.iteritems():
			schema = info['schema']
			gsettings = self._gsettings[schema]
			keys = gsettings.list_keys()
			if key in keys:
				LOG.debug("Listening to changes to %s.%s", schema, key)
				self._saved[key] = {
					'value': None,
					'handler_id': gsettings.connect('changed::' + key, lambda _, k: self._changed(k))
				}
				self._changed(key, init=True)
			else:
				LOG.debug("%s.%s does not exist, skipping", schema, key)

	def deactivate(self):
		if self._saved:
			for key, info in self._saved.iteritems():
				schema = self.SETTINGS[key]['schema']
				self._set_setting(key, info['value'])
				LOG.debug("Disconnecting %s.%s", schema, key)
				self._gsettings[schema].disconnect(info['handler_id'])

		self._gsettings = None
		self._saved = None

	def _get_setting(self, key):
		info = self.SETTINGS[key]
		return getattr(self._gsettings[info['schema']], 'get_' + info['type'])(key)

	def _set_setting(self, key, value, ret=None):
		info = self.SETTINGS[key]
		schema = info['schema']
		gsettings = self._gsettings[schema]
		handler_id = self._saved[key]['handler_id']

		LOG.debug("Setting %s.%s to %s", schema, key, value)
		gsettings.handler_block(handler_id)
		result = getattr(gsettings, 'set_' + info['type'])(key, value)
		gsettings.sync()
		gsettings.handler_unblock(handler_id)
		if not result:
			LOG.warning("Unable to set %s.%s to %s", schema, key, value)

		return ret if ret is not None else result # for _changed()

	def _changed(self, key, init=False):
		info = self.SETTINGS[key]
		schema = info['schema']
		value = self._get_setting(key)
		if init:
			LOG.debug("Saving initial value %s for %s.%s", value, schema, key)
		else:
			LOG.debug("%s.%s changed to %s", schema, key, value)

		self._saved[key]['value'] = value

		clamp = info['clamp']
		if value != clamp:
			GLib.idle_add(self._set_setting, key, clamp, False)


def main(argv):
	parser = optparse.OptionParser(description="faux-gnome-screensaver - a GNOME compatibility layer for XScreenSaver")
	parser.add_option('--no-daemon', action='store_true', dest='no_daemon', default=False, help="Don't become a daemon (not implemented)")
	parser.add_option('--debug', action='store_true', dest='debug', default=False, help="Enable debugging code")
	parser.add_option('--no-dpms', action='store_true', dest='no_dpms', default=False, help="Don't manage DPMS (Energy Star) features")

	options, args = parser.parse_args()

	logging_level = logging.DEBUG if options.debug else logging.INFO
	logging.basicConfig(format=LOG_FORMAT, level=logging_level)

	DBusGMainLoop(set_as_default=True)
	mainloop = GLib.MainLoop()

	def quit(signum=None):
		if signum is not None:
			LOG.debug("Received signal %d, leaving main loop", signum)
		else:
			LOG.debug("Leaving main loop")
		mainloop.quit()

	sighup_id = GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGHUP, quit, signal.SIGHUP)
	sigterm_id = GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGTERM, quit, signal.SIGTERM)

	gset_manager = GSettingsManager()
	xss_manager = XScreenSaverManager(options.no_dpms)
	gs_service = FauxGnomeScreensaverService()
	gsm_listener = GnomeSessionManagerListener()
	ck_listener = ConsoleKitListener()

	xss_manager_ids = []
	for s, h in [
				('active-changed', lambda _, a: gs_service.active_changed(a))
			]:
		xss_manager_ids.append(xss_manager.connect(s, h))

	gs_service_ids = []
	for s, h in [
				('quit', lambda _: quit()),
				('lock', lambda _: xss_manager.lock()),
				('simulate-user-activity', lambda _: xss_manager.simulate_user_activity()),
				('set-active', lambda _, v: setattr(xss_manager, 'active', v)),
				('get-active', lambda _: xss_manager.active),
				('get-active-time', lambda _: xss_manager.active_time)
			]:
		gs_service_ids.append(gs_service.connect(s, h))

	gsm_listener_ids = []
	for s, h in [
				('inhibited-changed', lambda _, i: xss_manager.inhibit() if i else xss_manager.uninhibit())
			]:
		gsm_listener_ids.append(gsm_listener.connect(s, h))

	ck_listener_ids = []
	for s, h in [
				('lock', lambda _: xss_manager.lock()),
				('unlock', lambda _: setattr(xss_manager, 'active', False)),
				('is-active', lambda _: xss_manager.simulate_user_activity()),
			]:
		ck_listener_ids.append(ck_listener.connect(s, h))

	for o in (gset_manager, xss_manager, gs_service, gsm_listener, ck_listener):
		o.activate()

	LOG.debug("Entering main loop")
	try:
		mainloop.run()
	except KeyboardInterrupt:
		LOG.debug("Received signal %d, leaving main loop", signal.SIGINT)

	GLib.source_remove(sighup_id)
	GLib.source_remove(sigterm_id)

	for o in (ck_listener, gsm_listener, gs_service, xss_manager, gset_manager):
		o.deactivate()

	for h in ck_listener_ids:
		ck_listener.disconnect(h)
	for h in gsm_listener_ids:
		gsm_listener.disconnect(h)
	for h in gs_service_ids:
		gs_service.disconnect(h)
	for h in xss_manager_ids:
		xss_manager.disconnect(h)


if __name__ == '__main__':
	argv = sys.argv
	basename = os.path.basename(argv[0])

	# there must be a better way
	if basename == 'gnome-screensaver':
		libc = ctypes.cdll.LoadLibrary('libc.so.6')
		libc.prctl(15, basename, 0, 0, 0)

	LOG = logging.getLogger(basename)

	sys.exit(main(argv))
