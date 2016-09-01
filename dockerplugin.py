#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Collectd plugin for collecting docker container stats
#
# Copyright © 2015 eNovance
#
# Authors:
#   Sylvain Baubeau <sylvain.baubeau@enovance.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Requirements: docker-py

import dateutil.parser
from calendar import timegm
from distutils.version import StrictVersion
import docker
import json
import jsonpath_rw
import logging
import os
import threading
import time
import sys

COLLECTION_INTERVAL = 10

def _c(c):
    """A helper method for representing a container in messages. If the given
    argument is a string, it is assumed to be the container's ID and only the
    first 7 digits will be returned. If it's a dictionary, the string returned
    is <7-digit ID>/<name>."""
    if type(c) == str or type(c) == unicode:
        return c[:7]
    return '{id}/{name}'.format(id=c['Id'][:7], name=c.get('Name', c['Names']))


def _d(d):
    """Formats a dictionary of key/value pairs as a comma-delimited list of
    key=value tokens."""
    return ','.join(['='.join(p) for p in d.items()])


def str_to_bool(value):
    """Python 2.x does not have a casting mechanism for booleans.  The built in
    bool() will return true for any string with a length greater than 0.  It
    does not cast a string with the text "true" or "false" to the
    corresponding bool value.  This method is a casting function.  It is
    insensetive to case and leading/trailing spaces.  An Exception is raised
    if a cast can not be made.
    """
    value = str(value).strip().lower()
    if value == 'true':
        return True
    elif value == 'false':
        return False
    else:
        raise ValueError('Unable to cast value (%s) to boolean' % value)


def emit(container, dimensions, point_type, value, t=None,
         type_instance=None):
    """Emit a collected datapoint."""
    log.info(('Value parameters to be emitted:'
              '\n container : {c}'
              '\n dimensions : {d}'
              '\n point_type : {pt}'
              '\n value : {v}'
              '\n type_instance : {ti} '
              '\n time : {t}').format(c=_c(container),
                                      d=dimensions,
                                      pt=point_type,
                                      v=value,
                                      ti=type_instance,
                                      t=time))
    val = collectd.Values()
    val.plugin = 'docker'
    val.plugin_instance = container['Name']

    # Add additional extracted dimensions through plugin_instance.
    if dimensions:
        val.plugin_instance += '[{dims}]'.format(dims=_d(dimensions))

    if point_type:
        val.type = point_type
    if type_instance:
        val.type_instance = type_instance

    if t:
        val.time = timegm(dateutil.parser.parse(t).utctimetuple())
    else:
        val.time = time.time()

    # With some versions of CollectD, a dummy metadata map must to be added
    # to each value for it to be correctly serialized to JSON by the
    # write_http plugin. See
    # https://github.com/collectd/collectd/issues/716
    val.meta = {'true': 'true'}

    val.values = value
    log.info('Value to be emitted {0}'.format(val))
    val.dispatch()


def read_blkio_stats(container, dimensions, stats, t):
    """Process block I/O stats for a container."""
    log.info('Reading blkio stats: {0}'.format(stats))
    for key, values in stats.items():
        # Block IO stats are reported by block device (with major/minor
        # numbers). We need to group and report the stats of each block
        # device independently.
        blkio_stats = {}
        blkio_major_stats = {}
        blkio_minor_stats = {}

        for value in values:

            k = '{key}-{major}-{minor}'.format(key=key,
                                               major=value['major'],
                                               minor=value['minor'])

            if k not in blkio_stats:
                blkio_stats[k] = []
            blkio_stats[k].append(value['value'])
            blkio_major_stats[k] = value['major']
            blkio_minor_stats[k] = value['minor']

        for type_instance, values in blkio_stats.items():
            # add block device major and minor as dimensions
            blkioDims = dimensions.copy()
            blkioDims['device_major'] = str(blkio_major_stats[type_instance])
            blkioDims['device_minor'] = str(blkio_minor_stats[type_instance])

            if len(values) == 5:
                emit(container, blkioDims, 'blkio', values,
                     type_instance=key, t=t)
            elif len(values) == 1:
                # For some reason, some fields contains only one value and
                # the 'op' field is empty. Need to investigate this
                emit(container, blkioDims, 'blkio.single', values,
                     type_instance=key, t=t)
            else:
                log.warning(('Unexpected number of blkio stats for '
                             'container {0}!')
                            .format(_c(container)))


def read_cpu_stats(container, dimensions, stats, t):
    """Process CPU utilization stats for a container."""
    log.info('Reading cpu stats: {0}'.format(stats))
    cpu_usage = stats['cpu_usage']
    percpu = cpu_usage['percpu_usage']
    for cpu, value in enumerate(percpu):
        percpuDims = dimensions.copy()
        percpuDims['core'] = ('cpu%d' % (cpu))
        emit(container, percpuDims, 'cpu.percpu.usage', [value],
             type_instance='', t=t)

    items = sorted(stats['throttling_data'].items())
    emit(container, dimensions, 'cpu.throttling_data',
         [x[1] for x in items], t=t)

    values = [cpu_usage['total_usage'], cpu_usage['usage_in_kernelmode'],
              cpu_usage['usage_in_usermode'], stats['system_cpu_usage']]
    emit(container, dimensions, 'cpu.usage', values, t=t)


def read_network_stats(container, dimensions, stats, t):
    """Process network utilization stats for a container."""
    log.info('Reading network stats: {0}'.format(stats))
    items = stats.items()
    items.sort()
    emit(container, dimensions, 'network.usage', [x[1] for x in items], t=t)


def read_memory_stats(container, dimensions, stats, t):
    """Process memory utilization stats for a container."""
    log.info('Reading memory stats: {0}'.format(stats))
    values = [stats['limit'], stats['max_usage'], stats['usage']]
    emit(container, dimensions, 'memory.usage', values, t=t)

    detailed = stats.get('stats')
    if detailed:
        for key, value in detailed.items():
            emit(container, dimensions, 'memory.stats', [value],
                 type_instance=key, t=t)
    else:
        log.notice('No detailed memory stats available from container {0}.'
                   .format(_c(container)))


class DimensionsProvider:
    """Helper class for performing dimension extraction from a given container.

    Dimensions to extract are specified via a "spec" following the syntax
    "<provider>:<source>". The provider defines the means by which the
    dimension value is extracted, and the source gives some information as to
    where to find the dimension value through this provider.

    Extracting dimensions values from the container's environment or from its
    JSON Docker details are supported, as well as specifying direct, raw
    values.
    """

    SUPPORTED_PROVIDERS = ['inspect', 'env', 'raw']

    def __init__(self, specs):
        self._specs = specs
        try:
            self._validate()
        except Exception as e:
            log.exception(e)
            raise e

    def _validate(self):
        """Validate the configured dimensions extraction specs."""
        for name, spec in self._specs.items():
            try:
                provider, _ = spec.split(':')
            except:
                raise Exception('Invalid configuration of provider for '
                                'dimension {dim}: {spec}'
                                .format(dim=name, spec=spec))

            if provider not in DimensionsProvider.SUPPORTED_PROVIDERS:
                raise Exception('Unknown dimnension provider {provider} '
                                'for dimension {dim}!'
                                .format(provider=provider, dim=name))

    def extract(self, client, container):
        dimensions = {}

        for name, spec in self._specs.items():
            provider, source = spec.split(':')
            value = None

            if provider == 'inspect' or provider == 'env':
                raw = client.inspect_container(container)
                env = dict((k, v) for k, v in map(lambda e: e.split('=', 1),
                                                  raw['Config']['Env']))

                if provider == 'inspect':
                    match = jsonpath_rw.parse(source).find(raw)
                    value = str(match[0].value) if match else None
                elif provider == 'env':
                    value = env.get(source)
            elif provider == 'raw':
                value = source

            if value:
                dimensions[name] = value

        return dimensions


class ContainerStats(threading.Thread):
    """
    A thread that continuously consumes the stats stream from a container,
    keeping the most recently read stats available for processing by CollectD.

    Such a mechanism is required because the first read from Docker's stats API
    endpoint can take up to one second. Hitting this endpoint for every
    container running on the system would only be feasible if the number of
    running containers was less than the polling interval of CollectD. Above
    that, and the whole thing breaks down. It is thus required to maintain open
    the stats stream and read from it, but because it is a continuous stream we
    need to be continuously consuming from it to make sure that when CollectD
    requests a plugin read, it gets the latest stats data from each container.

    The role of this thread is to keep consuming from the stats endpoint (it's
    a blocking stream read, getting stats data from the Docker daemon every
    second), and make the most recently read data available in a variable.
    """

    def __init__(self, container, dimensions, client):
        threading.Thread.__init__(self)
        self.daemon = True
        self.stop = False

        self._container = container
        self._client = client
        self._feed = None
        self._stats = None

        # Extract dimensions values
        self.dimensions = {}
        if dimensions:
            self.dimensions.update(dimensions.extract(self._client,
                                                      self._container))

        # Automatically start stats reading thread
        self.start()

    def run(self):
        log.info('Starting stats gathering for {container} ({dims}).'
                 .format(container=_c(self._container),
                         dims=_d(self.dimensions)))

        failures = 0
        while not self.stop:
            try:
                if not self._feed:
                    self._feed = self._client.stats(self._container)
                self._stats = self._feed.next()

                # Reset failure count on successfull read from the stats API.
                failures = 0
            except Exception, e:
                # If we encounter a failure, wait a second before retrying and
                # mark the failures. After three consecutive failures, we'll
                # stop the thread. If the container is still there, we'll spin
                # up a new stats gathering thread the next time read_callback()
                # gets called by CollectD.
                time.sleep(1)
                failures += 1
                if failures > 3:
                    log.exception(('Unable to read stats from {container}: '
                                  '{msg}')
                                  .format(container=_c(self._container),
                                          msg=e))
                    self.stop = True

                # Marking the feed as dead so we'll attempt to recreate it and
                # survive transient Docker daemon errors/unavailabilities.
                self._feed = None

        log.info('Stopped stats gathering for {0}.'
                 .format(_c(self._container)))

    @property
    def stats(self):
        """Wait, if needed, for stats to be available and return the most
        recently read stats data, parsed as JSON, for the container."""
        if self._stats:
            return json.loads(self._stats)
        return None


class DockerPlugin:
    """
    CollectD plugin for collecting statistics about running containers via
    Docker's remote API /<container>/stats endpoint.
    """

    DEFAULT_BASE_URL = 'unix://var/run/docker.sock'
    DEFAULT_DOCKER_TIMEOUT = 5

    # The stats endpoint is only supported by API >= 1.17
    MIN_DOCKER_API_VERSION = '1.17'

    # TODO: add support for 'networks' from API >= 1.20 to get by-iface stats.
    METHODS = {'network': read_network_stats,
               'blkio_stats': read_blkio_stats,
               'cpu_stats': read_cpu_stats,
               'memory_stats': read_memory_stats}

    def __init__(self, docker_url=None):
        self.docker_url = docker_url or DockerPlugin.DEFAULT_BASE_URL
        self.timeout = DockerPlugin.DEFAULT_DOCKER_TIMEOUT
        self.capture = False
        self.dimensions = None
        self.stats = {}

    def _container_name(self, names):
        """Extract the true container name from the list of container names
        sent back by the Docker API. The list of container names contains the
        names of linked containers too ('/other/alias' for example), but we're
        only interested in the true container's name, '/foo'."""
        for name in names:
            split = name.split('/')
            if len(split) == 2:
                return split[1]
        raise Exception('Cannot find valid container name in {names}'
                        .format(names=names))

    def configure_callback(self, conf):
        specs = {}

        global COLLECTION_INTERVAL

        for node in conf.children:
            try:
                if node.key == 'BaseURL':
                    self.docker_url = node.values[0]
                elif node.key == 'Timeout':
                    self.timeout = int(node.values[0])
                elif node.key == 'Dimension':
                    specs[node.values[0]] = node.values[1]
                elif node.key == 'Verbose':
                    handle.verbose = str_to_bool(node.values[0])
		elif node.key == 'Interval':
		    COLLECTION_INTERVAL = int(node.values[0])
            except Exception as e:
                log.error('Failed to load the configuration %s due to %s'
                          % (node.key, e))
                raise e

        self.dimensions = DimensionsProvider(specs)

    def init_callback(self):
        self.client = docker.Client(
                base_url=self.docker_url,
                version=DockerPlugin.MIN_DOCKER_API_VERSION)
        self.client.timeout = self.timeout

        # Check API version for stats endpoint support.
        try:
            version = self.client.version()['ApiVersion']
            if StrictVersion(version) < \
                    StrictVersion(DockerPlugin.MIN_DOCKER_API_VERSION):
                raise Exception
        except:
            log.exception(('Docker daemon at {0} does not '
                           'support container statistics!')
                          .format(self.docker_url))
            return False

        collectd.register_read(self.read_callback, interval=COLLECTION_INTERVAL)
        log.notice(('Collecting stats about Docker containers from {url} '
                    '(API version {version}; timeout: {timeout}s).')
                   .format(url=self.docker_url,
                           version=version,
                           timeout=self.timeout))
        return True

    def read_callback(self):
        try:
            containers = [c for c in self.client.containers()
                          if c['Status'].startswith('Up')]
            # Log the list of containers retrieved
            log.info('The following containers were fetched from {url}: '
                     '{c}'.format(url=self.docker_url, c=containers))
        except Exception as e:
            containers = []
            log.exception(('Failed to retrieve containers info from {url} '
                           'This may indicate that the docker api is '
                           'inaccessible or that there are no running '
                           'containers. : {error}')
                          .format(url=self.docker_url,
                                  error=e))

        # Terminate stats gathering threads for containers that are not running
        # anymore.
        for cid in set(self.stats) - set(map(lambda c: c['Id'], containers)):
            # Log each container that is stopped
            self.stats[cid].stop = True
            log.info('Stopping stats gathering for {0}'
                     .format(_c(self.stats[cid]._container)))
            del self.stats[cid]

        for container in containers:
            try:
                container['Name'] = self._container_name(container['Names'])

                # Start a stats gathering thread if the container is new.
                if container['Id'] not in self.stats:
                    self.stats[container['Id']] = \
                            ContainerStats(container, self.dimensions,
                                           self.client)

                cstats = self.stats[container['Id']]
                stats = cstats.stats
                read_at = stats.get('read') if stats else None
                if not read_at:
                    # No stats available yet; skipping container.
                    continue

                # Process stats through each reader.
                for key, method in self.METHODS.items():
                    value = stats.get(key)
                    if value:
                        method(container, cstats.dimensions, value, read_at)
            except Exception, e:
                log.exception(('Unable to retrieve stats for container '
                               '{container}: {msg}')
                              .format(container=_c(container), msg=e))


class CollectdLogHandler(logging.Handler):
    """Log handler to forward statements to collectd
    A custom log handler that forwards log messages raised
    at level debug, info, notice, warning, and error
    to collectd's built in logging.  Suppresses extraneous
    info and debug statements using a "verbose" boolean

    Inherits from logging.Handler

    Arguments
        plugin -- name of the plugin (default 'unknown')
        verbose -- enable/disable verbose messages (default False)
    """
    def __init__(self, plugin="unknown", verbose=False):
        """Initializes CollectdLogHandler
        Arguments
            plugin -- string name of the plugin (default 'unknown')
            verbose -- enable/disable verbose messages (default False)
        """
        self.verbose = verbose
        self.plugin = plugin
        logging.Handler.__init__(self, level=logging.NOTSET)

    def emit(self, record):
        """
        Emits a log record to the appropraite collectd log function

        Arguments
        record -- str log record to be emitted
        """
        try:
            if record.msg is not None:
                if record.levelname == 'ERROR':
                    collectd.error('%s : %s' % (self.plugin, record.msg))
                elif record.levelname == 'WARNING':
                    collectd.warning('%s : %s' % (self.plugin, record.msg))
                elif record.levelname == 'NOTICE':
                    collectd.notice('%s : %s' % (self.plugin, record.msg))
                elif record.levelname == 'INFO' and self.verbose is True:
                    collectd.info('%s : %s' % (self.plugin, record.msg))
                elif record.levelname == 'DEBUG' and self.verbose is True:
                    collectd.debug('%s : %s' % (self.plugin, record.msg))
        except Exception as e:
            collectd.warning(('{p} [ERROR]: Failed to write log statement due '
                              'to: {e}').format(p=self.plugin,
                                                e=e
                                                ))


class CollectdLogger(logging.Logger):
    """Logs all collectd log levels via python's logging library
    Custom python logger that forwards log statements at
    level: debug, info, notice, warning, error

    Inherits from logging.Logger

    Arguments
    name -- name of the logger
    level -- log level to filter by
    """
    def __init__(self, name, level=logging.NOTSET):
        """Initializes CollectdLogger

        Arguments
        name -- name of the logger
        level -- log level to filter by
        """
        logging.Logger.__init__(self, name, level)
        logging.addLevelName(25, 'NOTICE')

    def notice(self, msg):
        """Logs a 'NOTICE' level statement at level 25

        Arguments
        msg - log statement to be logged as 'NOTICE'
        """
        self.log(25, msg)


# Set up logging
logging.setLoggerClass(CollectdLogger)
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.propagate = False
handle = CollectdLogHandler('docker')
log.addHandler(handle)

# Command-line execution
if __name__ == '__main__':
    class ExecCollectdValues:
        def dispatch(self):
            if not getattr(self, 'host', None):
                self.host = os.environ.get('COLLECTD_HOSTNAME', 'localhost')
            identifier = '%s/%s' % (self.host, self.plugin)
            if getattr(self, 'plugin_instance', None):
                identifier += '-' + self.plugin_instance
            identifier += '/' + self.type
            if getattr(self, 'type_instance', None):
                identifier += '-' + self.type_instance
            print 'PUTVAL', identifier, \
                  ':'.join(map(str, [int(self.time)] + self.values))

    class ExecCollectd:
        def Values(self):
            return ExecCollectdValues()

        def register_read(self, callback):
            pass

        def error(self, msg):
            print 'ERROR: ', msg

        def warning(self, msg):
            print 'WARNING:', msg

        def notice(self, msg):
            print 'NOTICE: ', msg

        def info(self, msg):
            print 'INFO:', msg

        def debug(self, msg):
            print 'DEBUG: ', msg

    collectd = ExecCollectd()
    plugin = DockerPlugin()
    if len(sys.argv) > 1:
        plugin.docker_url = sys.argv[1]

    if not plugin.init_callback():
        sys.exit(1)

    while True:
        plugin.read_callback()
        time.sleep(5)


# Normal plugin execution via CollectD
else:
    import collectd
    plugin = DockerPlugin()
    collectd.register_config(plugin.configure_callback)
    collectd.register_init(plugin.init_callback)
