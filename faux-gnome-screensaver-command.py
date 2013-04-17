#!/usr/bin/env python
#
# faux-gnome-screensaver-command.py
# This file is part of faux-gnome-screensaver
#
# Copyright (C) 2012 Jeffery To <jeffery.to@gmail.com>
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

import dbus
import logging
import optparse
import os
import sys

VERSION = '0.2.0'

GS_SERVICE = 'org.gnome.ScreenSaver'
GS_PATH = '/org/gnome/ScreenSaver'
GS_INTERFACE = 'org.gnome.ScreenSaver'

LOG = logging.getLogger(__name__)
LOG_FORMAT = '%(name)s %(levelname)s: %(message)s'


def main(argv):
	parser = optparse.OptionParser(description="faux-gnome-screensaver-command - controls faux-gnome-screensaver")
	parser.add_option('--exit', action='store_true', dest='exit', default=False, help="Causes the screensaver to exit gracefully")
	parser.add_option('-q', '--query', action='store_true', dest='query', default=False, help="Query the state of the screensaver")
	parser.add_option('-t', '--time', action='store_true', dest='time', default=False, help="Query the length of time the screensaver has been active")
	parser.add_option('-l', '--lock', action='store_true', dest='lock', default=False, help="Tells the running screensaver process to lock the screen immediately")
	parser.add_option('-a', '--activate', action='store_true', dest='activate', default=False, help="Turn the screensaver on (blank the screen)")
	parser.add_option('-d', '--deactivate', action='store_true', dest='deactivate', default=False, help="If the screensaver is active then deactivate it (un-blank the screen)")
	parser.add_option('-V', '--version', action='store_true', dest='version', default=False, help="Version of this application")

	options, args = parser.parse_args()

	logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

	if options.version:
		print("%s %s" % (argv[0], VERSION))
		return

	bus = dbus.SessionBus()
	try:
		proxy = bus.get_object(GS_SERVICE, GS_PATH)
	except dbus.exceptions.DBusException as err:
		LOG.info("Could not get dbus object: %s", err)
		return 1
	iface = dbus.Interface(proxy, dbus_interface=GS_INTERFACE)

	if options.exit:
		iface.Quit()
		return

	if options.query:
		if iface.GetActive():
			print("The screensaver is active")
		else:
			print("The screensaver is inactive")

	if options.time:
		if iface.GetActive():
			# TODO use ngettext
			seconds = iface.GetActiveTime()
			if seconds == 1:
				print("The screensaver is has been active for 1 second.")
			else:
				print("The screensaver is has been active for %d seconds." % (seconds,))
		else:
			print("The screensaver is not currently active.")

	if options.lock:
		iface.Lock()

	if options.activate:
		iface.SetActive(True)

	if options.deactivate:
		iface.SetActive(False)

	
if __name__ == '__main__':
	argv = sys.argv
	basename = os.path.basename(argv[0])

	LOG = logging.getLogger(basename)

	sys.exit(main(argv))

