# docker-collectd-plugin

A [Docker](http://docker.io) plugin for [collectd](http://collectd.org)
using [docker-py](https://github.com/docker/docker-py) and collectd's
[Python plugin](http://collectd.org/documentation/manpages/collectd-python.5.shtml).

This uses the new stats API [introduced by
\#9984](https://github.com/docker/docker/pull/9984) in Docker 1.5.

The following container stats are gathered for each container, with
examples of some of the metric names reported:

* Network bandwidth:
 * `network.usage.rx_bytes`
 * `network.usage.tx_bytes`
 * ...
* Memory usage:
 * `memory.usage.total`
 * `memory.usage.limit`
 * ...
* CPU usage:
 * `cpu.usage.total`
 * `cpu.usage.system`
 * ...
* Block IO:
 * `blockio.io_service_bytes_recursive-<major>-<minor>.read`
 * `blockio.io_service_bytes_recursive-<major>-<minor>.write`
 * ...

All metrics are reported with a `plugin:docker` dimension, and the name
of the container is used for the `plugin_instance` dimension.

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

### Extracting additional dimensions

The plugin has the ability to extract additional information about or
from the monitored container and report them as extra dimensions on your
metrics. The general syntax is via the `Dimension` directive in the
`Module` section:

```
<Module dockerplugin>
  ...
  Dimension "<name>" "<spec>"
</Module>
```

Where `<name>` is the name of the dimension you want to add, and
`<spec>` describes how the value for this dimension should be extracted
by the plugin. You can extract:

- manually specified dimension values, with `raw:foobar`;
- container environment variable values, with `env:ENV_VAR_NAME`;
- any container detail value from Docker, with `inspect:Path.In.Json`.

Here are some examples:

```
Dimension "mesos_task_id" "env:MESOS_TASK_ID"
Dimension "image" "inspect:Config.Image"
Dimension "foo" "raw:bar"
```

For `inspect`, the parameter is expected to be a JSONPath matcher giving
the path to the value you're interested in within the JSON output of
`docker inspect` (or `/containers/<container>/json` via the remote API).
See https://github.com/kennknowles/python-jsonpath-rw for more details
about the JSONPath syntax.

### Important note about additional dimensions

The additional dimensions extracted by this `docker-collectd-plugin` are
packed into the `plugin_instance` dimension using the following syntax:

```
plugin_instance:value[dim1=value1,dim2=value2,...]
```

Because CollectD limits the size of the reported fields to 64 total
characters, trying to pack too many additional dimensions will result in
the whole constructed string from being truncated, making parsing those
additional dimensions correctly on the target metrics system impossible.
You should make sure that the total size of your `plugin_instance`
value, including all additional dimensions names and values, does not
exceed 64 characters.

## Requirements

* Docker 1.5+
* `docker-py`
* `jsonpath_rw`
* `python-dateutil`
