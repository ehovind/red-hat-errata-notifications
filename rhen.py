#!/usr/bin/python3
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
import logging
import logging.config
import configparser
import os
import signal
import argparse
import atexit
import sys

from lib.rhen_dbus import RHENDbus
from lib.rhen_db import RHENdb
from lib.rhen_parser import RHENParser
from lib.rhen_schedule import RHENSchedule

class RedHatErrataNotify(object):
    CONFIG = os.getcwd() + '/config/rhen.ini'
    CONFIG_LOG = os.getcwd() + '/config/rhen-log.ini'

    def __init__(self, args):
        self.args = args
        self.cfg = self.read_config()
        self.logger = self.setup_logging()
        signal.signal(signal.SIGINT, self.cleanup)

        self.rhen_schedule = self.init_schedule()
        self.rhen_dbus = self.init_dbus()
        self.rhen_db = self.init_db()
        self.rhen_parser = self.init_parser()

    def init_schedule(self):
        return RHENSchedule(self.cfg, self.logger)

    def init_dbus(self):
        return RHENDbus(self.cfg, self.logger)

    def init_db(self):
        return RHENdb(self.cfg, self.logger)

    def init_parser(self):
        return RHENParser(self.cfg, self.logger, self.rhen_db, self.rhen_dbus)

    def setup_logging(self):
        logging.config.fileConfig(self.CONFIG_LOG)
        logger = logging.getLogger()
        if self.args['verbose']:
            logger.setLevel(logging.INFO)
        if self.args['debug']:
            logger.setLevel(logging.DEBUG)
        return logger

    def read_config(self):
        try:
            cfg = configparser.ConfigParser()
            cfg.read(self.CONFIG)
            return cfg
        except (configparser.Error, IOError) as err:
            self.logger.error("Failed reading config file: %s" % err)
            raise SystemExit(1)

    def run(self):
        """
            Load RSS feed and compare with already seen erratas.
            If new errata, send notification and store in db.
            Schedule a new errata check.
        """
        self.logger.info("Parsing erratas")
        self.rhen_parser.parse_errata()
        self.rhen_schedule.next_check_errata(self.run)

    def list_erratas(self, category):
        """ List all erratas in category """
        erratas_all = self.rhen_db.list_all()
        erratas = [errata for errata in erratas_all if errata[0].startswith(category)]
        for errata in erratas:
            print("{advisory:<16s}{cvss2:<5}{synopsis:<64s}{date:16s}".format(advisory=errata[0],
            cvss2=errata[2], synopsis=errata[1], date=errata[3].strftime('%Y-%m-%d %H:%M:%S')))

    def cleanup(self, signo, frame):
        print("Cleaning up")
        self.rhen_schedule.cancel_check_errata()
        raise SystemExit(0)

def launch_daemon(pid='tmp/rhen.pid', stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
    if os.path.exists(pid):
        raise RuntimeError("rhen.py is already running\n")

    # Detach from parent. Fork and exit parent.
    try:
        if os.fork() > 0:
            raise SystemExit(0)
    except OSError as err:
        raise RuntimeError("Failed parent detach: %s" % err)

    os.umask(0)
    os.setsid()

    sys.stdout.flush()
    sys.stderr.flush()

    with open(stdin, 'rb', 0) as fd:
        os.dup2(fd.fileno(), sys.stdin.fileno())
    with open(stdout, 'ab', 0) as fd:
        os.dup2(fd.fileno(), sys.stdout.fileno())
    with open(stderr, 'ab', 0) as fd:
        os.dup2(fd.fileno(), sys.stderr.fileno())

    with open(pid, 'w') as fd:
        fd.write(str(os.getpid()))

    atexit.register(lambda: os.remove(pid))

    def sigterm_handler(signo, frame):
        sys.stdout.write("Daemon stopped\n")
        raise SystemExit(1)

    signal.signal(signal.SIGTERM, sigterm_handler)
    sys.stdout.write('Daemon started (pid {pid})\n'.format(pid=os.getpid()))

def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--mode", choices=['daemon-start', 'daemon-stop', 'fg'], default='fg',
            help="Start RHEN in daemon or foreground (default: fg")
    parser.add_argument("--list", choices=['RHSA', 'RHBA', 'RHEA'], help="List erratas.")
    parser.add_argument("--verbose", action='store_true', help="Display extra information.")
    parser.add_argument("--debug", action='store_true', help="Display debug information.")

    return vars(parser.parse_args())

def main(args):
    red_hat_errata_notify = RedHatErrataNotify(args)

    if args['list']:
        red_hat_errata_notify.list_erratas(args['list'])
    else:
        red_hat_errata_notify.run()

if __name__ == '__main__':
    pid_file = 'tmp/rhen.pid'
    args = parse_args()

    if not os.path.exists('logs'):
        os.mkdir('logs')
    if not os.path.exists('tmp'):
        os.mkdir('tmp', 0o755)

    if args['mode'] == 'fg':
        main(args)

    if args['mode'] == 'daemon-start':
        try:
            launch_daemon(pid='tmp/rhen.pid', stdout='logs/stdout.log', stderr='logs/stderr.log')
        except RuntimeError as err:
            sys.stderr.write(str(err))
            raise SystemExit(1)
        main(args)

    if args['mode'] == 'daemon-stop':
        if os.path.exists(pid_file):
            with open(pid_file) as f:
                os.kill(int(f.read()), signal.SIGTERM)
        else:
            sys.stderr.write('rhen.py is not running\n')
            raise SystemExit(1)
