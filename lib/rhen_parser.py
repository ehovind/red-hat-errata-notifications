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
import urllib
import re
import requests
import collections
from lxml import etree
import queue
import threading
import time
import configparser

class RHENParser(object):

    def __init__(self, cfg, logger, rhen_db, rhen_dbus):
        self.cfg = cfg
        self.logger = logger
        self.rhen_db = rhen_db
        self.rhen_dbus = rhen_dbus
        self.cve_base, self.errata_rss = self.parse_config()
        self.parser = self.init_parser()

    def parse_config(self):
        try:
            cve_base = self.cfg.get('main', 'cve')
            errata_rss = self.cfg.get('main', 'errata_rss')
            return (cve_base, errata_rss)
        except configparser.Error as err:
            self.logger.error("Failed parsing config: %s" % err)
            raise SystemExit(1)

    def init_parser(self):
        return etree.XMLParser(ns_clean=True, recover=True)

    def parse_errata(self):
        """ Load RSS and compare with previous erratas."""
        doc = self.load_rss_fead()

        for errata_item in doc.iterfind('channel/item'):
            title = errata_item.findtext('title')
            advisory = self.parse_errata_advisory(title)
            # Skip already seen erratas
            if self.rhen_db.find_errata(advisory) is not None:
                continue

            errata = self.parse_errata_content(advisory, errata_item)
            self.rhen_dbus.notify(errata)
            self.rhen_db.add_errata(errata)

    def load_rss_fead(self):
        try:
            self.logger.info("Loading RSS feed")
            erratas = urllib.request.urlopen(self.errata_rss)
            self.logger.debug(erratas.info()._headers)
            return etree.parse(erratas, self.parser)
        except (IOError, etree.XMLSyntaxError) as err:
            self.logger.error("Failed parsing rss feed: %s" % err)

    def parse_errata_advisory(self, title):
        try:
            return re.search(r'^(.*?)-1:\s(.*)$', title).group(1)
        except IndexError as err:
            self.logger.error("Failed parsing advisory: %s" % err)

    def parse_errata_synopsis(self, title):
        try:
            return re.search(r'^(.*?)-1:\s(.*)$', title).group(2)
        except IndexError as err:
            self.logger.error("Failed parsing synopsis: %s" % err)

    def parse_errata_cve(self, description):
        """ Return list of CVEs in advisory. Empty list if none found."""
        return re.findall(r'CVE-\d{4}-\d{4}', description, re.MULTILINE)

    def parse_errata_content(self, advisory, errata_item):
        errata = dict()

        errata['advisory'] = advisory
        errata['synopsis'] = self.parse_errata_synopsis(errata_item.findtext('title'))
        errata['link'] = errata_item.findtext('link')

        if 'RHSA' in advisory:
            cve = self.parse_errata_cve(errata_item.findtext('description'))
            if len(cve) == 0:
                self.logger.error("Could not find CVEs for security advisory %s" % advisory)
                return errata
            errata['cvss2'] = self.get_cvss2_score(cve)
        return errata

    def get_cvss2_score(self, CVE):
        start = time.time()
        cvss2_scores = collections.deque()
        q = queue.Queue()

        for worker in range(self.cfg.getint('processor', 'workers')):
            t = threading.Thread(target=self.cvss2_consumer, args=((q, cvss2_scores, False)))
            t.daemon = True
            t.start()

        self.cvss2_producer(q, CVE)
        q.join()
        self.logger.debug("Threading timing: " + str(time.time() - start))
        return max(cvss2_scores)

    def cvss2_producer(self, q, CVE):
        """ Put the CVEs on queue, so consumers can get and process. """
        try:
            for cve in CVE:
                q.put(cve)
        except queue.Full as err:
            self.logger.error("Queue is full: %s", err)

    def cvss2_consumer(self, q, cvss2_scores, lock=False):
        """
            Get CVE from queue, load CVE web page and extract the CVSS2 base score.
            Signal producer after finished processing item.
            If no CVE is found, no entry is added to queue and cvss2 is not displayed.
        """
        while True:
            try:
                cve = q.get()
                page = requests.get(self.cve_base + cve)
                doc = etree.fromstring(page.text, self.parser)

                # Extrac CVSS2 base score from page
                cvss2 = float(doc.xpath("//table/tr[th='Base Score:']/td")[0].text)

                # Append to thread safe queue
                cvss2_scores.append(cvss2)

            except requests.ConnectionError as err:
                self.logger.error("Failed connecting: %s", err)
            except queue.Empty as err:
                self.logger.error("Queue is empty: %s", err)
            except IndexError as err:
                self.logger.error("Failed parsing CVSS2 base score: %s", err)
            finally:
                q.task_done()
