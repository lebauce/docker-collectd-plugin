# docker-collectd-plugin

[![Build Status](https://travis-ci.org/lebauce/docker-collectd-plugin.svg?branch=master)](https://travis-ci.org/lebauce/docker-collectd-plugin)

A [Docker](http://docker.io) plugin for [collectd](http://collectd.org)
using [docker-py](https://github.com/docker/docker-py) and collectd's
[Python plugin](http://collectd.org/documentation/manpages/collectd-python.5.shtml).

This uses the new stats API (https://github.com/docker/docker/pull/9984)
introduced by Docker 1.5.

The following container stats are reported for each container:

* Network bandwidth
* Memory usage
* CPU usage
* Block IO

The name of the container is used for the `plugin_instance` dimension.

## Install

1. Checkout this repository somewhere on your system accessible by
   collectd; for example as
   `/usr/share/collectd/docker-collectd-plugin`.
1. Install the Python requirements with `pip install -r
   requirements.txt`.
1. Configure the plugin (see below).
1. Restart collectd.

## Configuration

Add the following to your collectd config:

```
TypesDB "/usr/share/collectd/docker-collectd-plugin/dockerplugin.db"
LoadPlugin python

<Plugin python>
  ModulePath "/usr/share/collectd/docker-collectd-plugin"
  Import "dockerplugin"

  <Module dockerplugin>
    BaseURL "unix://var/run/docker.sock"
    Timeout 3
  </Module>
</Plugin>
```

## Requirements

* docker-py
* python-dateutil
* docker 1.5+
