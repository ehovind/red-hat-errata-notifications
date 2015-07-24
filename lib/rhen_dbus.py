"""
This file is part of Red Hat Errata Notifications (rhen.py).
Copyright (C) 2015 Espen Hovind <espehov@ifi.uio.no>

rhen.py is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

rhen.py is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with rhen.py.  If not, see <http://www.gnu.org/licenses/>.
"""
import dbus
import jinja2
import configparser

class RHENDbus(object):
    def __init__(self, cfg, logger):
        self.cfg = cfg
        self.logger = logger
        self.item, self.path, self.interface = self.parse_config()
        self.notifier = self.init_notifier()

    def parse_config(self):
        try:
            item = self.cfg.get('dbus', 'item')
            path = self.cfg.get('dbus', 'path')
            interface = self.cfg.get('dbus', 'interface')
            return (item, path, interface)
        except configparser.Error as err:
            self.logger.error("Failed parsing config: %s" % err)
            raise SystemExit(1)

    def init_notifier(self):
        try:
            bus = dbus.SessionBus()
            notify_proxy = bus.get_object(self.item, self.path)
            return dbus.Interface(notify_proxy, self.interface)
        except dbus.exceptions.DBusException as err:
            self.logger.error("Failed dbus setup: %s" % err)

    def notify(self, errata):
        message = self.construct_message(errata)
        self.send(message.splitlines()[0], '\r'.join(message.splitlines()[1:]))

    def construct_message(self, data):
        try:
            env = jinja2.Environment(loader=jinja2.PackageLoader('rhen', 'templates'))
            template = env.get_template('notification.jin')
            return template.render(data=data)
        except jinja2.TemplateError as err:
            self.logger.error("Failed constructing message: %s" % err)

    def send(self, summary, description):
        """
        Method signature: https://developer.gnome.org/notification-spec/
        """
        try:
            self.notifier.Notify(self.cfg.get('dbus', 'app_name'), 0,
                                 self.cfg.get('dbus', 'app_icon'),
                                 summary, description,
                                 '', '', self.cfg.getint('dbus', 'timeout'))
        except dbus.exceptions.DBusException as err:
            self.logger.error("Failed sending notification: %s" % err)
