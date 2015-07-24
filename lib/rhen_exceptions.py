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
class DBNotFound(Exception):
    """ Raise exception when db does not exist """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
