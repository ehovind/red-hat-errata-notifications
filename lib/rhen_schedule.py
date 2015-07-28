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
import sched
import time
import configparser

class RHENSchedule(object):
    def __init__(self, cfg, logger):
        self.cfg = cfg
        self.logger = logger
        self.event_id = None
        self.check_interval = self.parse_config()
        self.scheduler = self.init_scheduler()

    def parse_config(self):
        try:
            return self.cfg.getint('notfications', 'check_errata_interval')
        except configparser.Error as err:
            self.logger.error("Failed parsing config: %s" % err)
            raise SystemExit(1)

    def init_scheduler(self):
        return sched.scheduler(time.time, time.sleep)

    def next_check_errata(self, func):
        self._event_id = self.scheduler.enter(self.check_interval, 1, func)
        self.logger.debug("Scheduled new check: %s", self._event_id)
        self.scheduler.run()

    def cancel_check_errata(self):
        if self.event_id:
            self.scheduler.cancel(self.event_id)

    @property
    def event_id(self):
        return self._event_id

    @event_id.setter
    def event_id(self, event_id):
        self._event_id = event_id

    def __repr__(self):
        return "RHENSchedule ({0.cfg!r}, {0.logger!r}, {0.event_id!r})".format(self)

    def __str__(self):
        return "str({0.cfg!s}, {0.logger!s}, {0.event_id!s})".format(self)
