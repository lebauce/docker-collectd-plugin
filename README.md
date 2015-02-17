docker-collectd-plugin
=====================

A [Docker](http://docker.io) plugin for [collectd](http://collectd.org) using [docker-py](https://github.com/docker/docker-py) and collectd's [Python plugin](http://collectd.org/documentation/manpages/collectd-python.5.shtml).

This uses the new stats API (https://github.com/docker/docker/pull/9984) introduced by Docker 1.5

 * Network bandwidth
 * Memory usage
 * CPU usage
 * Block IO

Install
-------
 1. Place `dockerplugin.py` and `dockerplugin.db` in `/usr/share/collectd` (this is only an example).
 2. Configure the plugin (see below).
 3. Restart collectd.

Configuration
-------------
Add the following to your collectd config:

    TypesDB "/usr/share/collectd/dockerplugin.db"
    LoadPlugin python

    <Plugin python>
      ModulePath "/usr/share/collectd"
      Import "dockerplugin"

      <Module dockerplugin>
        BaseURL "unix://var/run/docker.sock"
      </Module>
    </Plugin>

Requirements
------------
 * docker-py
 * python-dateutil
 * docker 1.5+
