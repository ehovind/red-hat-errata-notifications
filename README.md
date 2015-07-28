Red Hat Errata Notifications (rhen.py)
==========================

### Description
Red Hat Errata Notifications (rhen.py) is a tool that do regular checks for new erratas from Red Hat, and displays a notification. rhen.py is licensed under GPLv3.
Security advisories CVEs are parsed to find the highest CVSS2 score.

rhen.py is using D-BUS for notifications, and is tested on Gnome Shell 3.16.

Project home page: https://github.com/ehovind/red-hat-errata-notifications

### Version
0.8.0

### Contributors
Espen Hovind (creator, maintainer)

### Installation
Clone this repository and install dependencies.

### Dependencies
- python 3
- jinja2
- lxml
- requests
- dbus

### Usage
Run ./rhen.py --help
