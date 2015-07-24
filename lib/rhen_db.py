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
import os
import sqlite3
import datetime
import configparser

import lib.rhen_exceptions as RHENExceptions

class RHENdb(object):
    def __init__(self, cfg, logger):
        self.logger = logger
        self.cfg = cfg
        self.db_path, self.db_schema = self.parse_config()
        self.conn, self.cursor = self.init_db()

    def parse_config(self):
        try:
            return (self.cfg.get('db', 'path'), self.cfg.get('db', 'schema'))
        except configparser.Error as err:
            self.logger.error("Failed parsing config: %s" % err)
            raise SystemExit(1)

    def init_db(self):
        """ Connect to db. If not existing, create first."""
        try:
            self.check()
        except RHENExceptions.DBNotFound as err:
            self.logger.info("Initializing db: %s" % err)
            self.create()
        finally:
            return self.connect()

    def create(self):
        try:
            conn = sqlite3.connect(self.db_path)
            with open(self.db_schema, 'rt') as fd:
                conn.executescript(fd.read())
                conn.commit()
        except sqlite3.OperationalError as err:
            self.logger.error("Failed to initalize db: %s" % err)
            raise SystemExit(1)

    def check(self):
        """ Check that db actually exists """
        try:
            os.stat(self.db_path)
        except FileNotFoundError as err:
            raise RHENExceptions.DBNotFound(err)

    def connect(self):
        try:
            conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
            cursor = conn.cursor()
            return (conn, cursor)
        except sqlite3.Error as err:
            self.logger.error("Failed connecting to db: %s" % err)
            raise SystemExit(1)

    def add_errata(self, errata):
        self.logger.info("Adding errata: %s", errata)
        try:
            # Commit if success. Rollback if any exceptions.
            with self.conn:
                self.cursor.execute("""
                    insert into erratas (advisory, synopsis, cvss2, date) values (?, ?, ?, ?)""",
                    (errata['advisory'], errata['synopsis'], errata.get('cvss2', ''),
                    datetime.datetime.now()))
        except sqlite3.IntegrityError as err:
            self.logger.error("Failed adding %s to db: %s" % (errata['advisory'], err))

    def find_errata(self, advisory):
        try:
            self.cursor.execute("select advisory from erratas where advisory = (?)", (advisory,))
            return self.cursor.fetchone()
        except sqlite3.Error as err:
            self.logger.error("Advisory not found %s: %s" % (advisory, err))

    def list_all(self):
        try:
            self.cursor.execute("select * from erratas order by date desc")
            return self.cursor.fetchall()
        except sqlite3.Error as err:
            self.logger.error("List all erratas failed: %s" % err)
