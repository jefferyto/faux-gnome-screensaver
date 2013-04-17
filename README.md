# Faux GNOME Screensaver #

A GNOME compatibility layer for XScreenSaver  
<https://github.com/jefferyto/faux-gnome-screensaver>  
v0.2.0

Faux GNOME Screensaver (FGS) adds several features to bridge the gap
between [XScreenSaver][] and GNOME 3:

*   FGS implements GNOME Screensaver's D-Bus interface. This allows, for
    instance, the **Lock** function in Ubuntu's session menu to
    correctly trigger XScreenSaver.

*   FGS obeys idle inhibition requests in the GNOME Session Manager.
    This allows programs like [Caffeine][] to request that the session
    not be marked as idle, thus preventing XScreenSaver from activating.

    *   If XScreenSaver is manually activated and locked, FSG will stop
        making deactivation requests so that the lock screen password
        prompt does not appear repeatedly.

*   FGS ensures that GNOME is configured to put XScreenSaver in control
    of screensaver activation and display power management.

This has only been tested under Ubuntu 12.10, but feedback (and patches)
for other distros would also be appreciated.

All bug reports, feature requests and miscellaneous comments are welcome
at the [project issue tracker][].

## Requirements ##

*   XScreenSaver
*   python-gi and python-dbus

## Installation ##

1.  Uninstall GNOME Screensaver:

        sudo apt-get remove gnome-screensaver

2.  Install XScreenSaver and dependencies:

        sudo apt-get install xscreensaver xscreensaver-gl-extra xscreensaver-data-extra python-gi python-dbus

3.  Download the source code (as [zip][] or [tar.gz][]) and extract.

4.  Copy program files into somewhere on your path, e.g.
    `/usr/local/bin`:

        sudo cp faux-gnome-screensaver.py faux-gnome-screensaver-command.py /usr/local/bin

5.  Make program files executable and link to their non-faux names:

        cd /usr/local/bin
        sudo chmod a+x faux-gnome-screensaver.py faux-gnome-screensaver-command.py
        sudo ln -s faux-gnome-screensaver.py gnome-screensaver
        sudo ln -s faux-gnome-screensaver-command.py gnome-screensaver-command

6.  Open **Startup Applications** (`gnome-session-properties`) and add
    an entry:

        Name: Screensaver
        Command: gnome-screensaver
        Comment: I'm too sexy for my screensaver

    faux-gnome-screensaver will start XScreenSaver so there is no need
    to add an entry for XScreenSaver.

7.  Log out and log back in to start faux-gnome-screensaver.

## Configuration ##

Open **Screensaver** (`xscreensaver-demo`) to configure XScreenSaver
(time to enable, time to power off display, etc.).

## Credits ##

Based in part on:

*   The script in a comment for [bug 528094][] by cpaul
*   The XScreenSaver inhibit code from [Caffeine][]

## License ##

Copyright &copy; 2012-2013 Jeffery To <jeffery.to@gmail.com>

Available under GNU General Public License version 3


[project issue tracker]: https://github.com/jefferyto/faux-gnome-screensaver/issues
[zip]: https://github.com/jefferyto/faux-gnome-screensaver/archive/master.zip
[tar.gz]: https://github.com/jefferyto/faux-gnome-screensaver/archive/master.tar.gz
[XScreenSaver]: http://www.jwz.org/xscreensaver/
[Caffeine]: https://launchpad.net/caffeine
[bug 528094]: https://bugs.launchpad.net/indicator-session/+bug/528094/comments/31
