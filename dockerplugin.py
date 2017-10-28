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
import docker
import jsonpath_rw
import logging
import os
import re
import sys
import threading
import time
from calendar import timegm
from datetime import datetime
from distutils.version import StrictVersion

COLLECTION_INTERVAL = 10
DEFAULT_SHARES = 1024


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
    insensitive to case and leading/trailing spaces.  An Exception is raised
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
    val.interval = COLLECTION_INTERVAL

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
    val.dispatch()


def read_blkio_stats(container, dimensions, stats, t):
    """Process block I/O stats for a container."""
    blkio_stats = stats['blkio_stats']
    log.info('Reading blkio stats: {0}'.format(blkio_stats))

    for key, values in blkio_stats.items():
        # Block IO stats are reported by block device (with major/minor
        # numbers). We need to group and report the stats of each block
        # device independently.
        device_stats = {}
        device_major_stats = {}
        device_minor_stats = {}

        for value in values:
            k = '{key}-{major}-{minor}'.format(key=key,
                                               major=value['major'],
                                               minor=value['minor'])

            if k not in device_stats:
                device_stats[k] = []
            device_stats[k].append(value['value'])
            device_major_stats[k] = value['major']
            device_minor_stats[k] = value['minor']

        for type_instance, values in device_stats.items():
            # add block device major and minor as dimensions
            blkio_dims = dimensions.copy()
            blkio_dims['device_major'] = str(device_major_stats[type_instance])
            blkio_dims['device_minor'] = str(device_minor_stats[type_instance])

            if len(values) == 5:
                emit(container, blkio_dims, 'blkio', values,
                     type_instance=key, t=t)
            elif len(values) == 1:
                # For some reason, some fields contains only one value and
                # the 'op' field is empty. Need to investigate this
                emit(container, blkio_dims, 'blkio.single', values,
                     type_instance=key, t=t)
            else:
                log.warning(('Unexpected number of blkio stats for '
                             'container {0}!')
                            .format(_c(container)))


def read_cpu_stats(container, dimensions, stats, t):
    """Process CPU utilization stats for a container."""
    cpu_stats = stats['cpu_stats']
    log.info('Reading cpu stats: {0}'.format(cpu_stats))

    cpu_usage = cpu_stats['cpu_usage']
    percpu = cpu_usage['percpu_usage']

    for cpu, value in enumerate(percpu):
        percpu_dims = dimensions.copy()
        percpu_dims['core'] = ('cpu%d' % cpu)
        emit(container, percpu_dims, 'cpu.percpu.usage', [value],
             type_instance='', t=t)

    items = sorted(cpu_stats['throttling_data'].items())
    emit(container, dimensions, 'cpu.throttling_data',
         [x[1] for x in items], t=t)

    system_cpu_usage = cpu_stats['system_cpu_usage']
    values = [cpu_usage['total_usage'], cpu_usage['usage_in_kernelmode'],
              cpu_usage['usage_in_usermode'], system_cpu_usage]
    emit(container, dimensions, 'cpu.usage', values, t=t)

    # CPU Percentage based on calculateCPUPercent Docker method
    # https://github.com/docker/docker/blob/master/api/client/stats.go
    cpu_percent = get_cpu_percent(stats)
    emit(container, dimensions, 'cpu.percent', [cpu_percent], t=t)


def get_cpu_percent(stats):
    cpu_percent = 0.0
    cpu_usage = stats['cpu_stats']['cpu_usage']
    if 'precpu_stats' in stats:
        precpu_stats = stats['precpu_stats']
        precpu_usage = precpu_stats['cpu_usage']
        percpu = cpu_usage['percpu_usage']
        cpu_delta = cpu_usage['total_usage'] - precpu_usage['total_usage']
        # Sometimes system_cpu_usage is not in cpu_stats (when there's load)
        if 'system_cpu_usage' in stats['cpu_stats']:
            system_cpu_usage = stats['cpu_stats']['system_cpu_usage']
            if 'system_cpu_usage' in precpu_stats:
                pre_system_cpu_usage = precpu_stats['system_cpu_usage']
                system_delta = float(system_cpu_usage - pre_system_cpu_usage)
                if system_delta > 0 and cpu_delta > 0:
                    cpu_percent = cpu_delta / system_delta * len(percpu)
                    cpu_percent *= 100
    return cpu_percent


def read_network_stats(container, dimensions, stats, t):
    """Process network utilization stats for a container."""
    net_stats = stats['networks']
    log.info('Reading network stats: {0}'.format(net_stats))

    for interface, if_stats in net_stats.items():
        items = sorted(if_stats.items())
        interface_dims = dimensions.copy()
        interface_dims['interface'] = interface
        emit(container,
             interface_dims,
             'network.usage',
             [x[1] for x in items],
             t=t)


def read_memory_stats(container, dimensions, stats, t):
    """Process memory utilization stats for a container."""
    mem_stats = stats['memory_stats']
    log.info('Reading memory stats: {0}'.format(mem_stats))

    values = [mem_stats['limit'], mem_stats['max_usage'], mem_stats['usage']]
    emit(container, dimensions, 'memory.usage', values, t=t)

    mem_percent = 100.0 * mem_stats['usage'] / mem_stats['limit']
    emit(container, dimensions, 'memory.percent', [mem_percent], t=t)

    detailed = mem_stats.get('stats')
    if detailed:
        for key, value in detailed.items():
            emit(container, dimensions, 'memory.stats', [value],
                 type_instance=key, t=t)
    else:
        log.notice('No detailed memory stats available from container {0}.'
                   .format(_c(container)))


def read_cpu_shares_stats(container,
                          container_inspect, cstats,
                          cpu_percent, sum_of_shares):
    # Get cpu shares used by container
    stats = cstats.stats
    dimensions = cstats.dimensions
    num_cpus_host = len(stats['cpu_stats']['cpu_usage']['percpu_usage'])
    shares_used_percent = 0.0
    cpu_shares = container_inspect['HostConfig']['CpuShares'] or \
        DEFAULT_SHARES
    fraction_of_shares = cpu_shares / float(sum_of_shares)
    shares_used_percent = cpu_percent / num_cpus_host / fraction_of_shares
    emit(container, dimensions,
         'cpu.shares',
         [shares_used_percent],
         type_instance='used.percent',
         t=stats['read'])


def read_cpu_quota_stats(container, container_inspect, cstats):
    stats = cstats.stats
    dimensions = cstats.dimensions
    host_config = container_inspect['HostConfig']
    cpu_quota = host_config.get('CpuQuota', 0)

    if not cpu_quota:
        return

    if 'preread' in stats and 'precpu_stats' in stats:
        period = host_config.get('CpuPeriod', 0)
        # Default period length is 100,000
        cpu_period = 100000 if period == 0 else period
        preread = datetime.strptime(
                stats['preread'][:-4],
                "%Y-%m-%dT%H:%M:%S.%f")
        read = datetime.strptime(
                stats['read'][:-4],
                "%Y-%m-%dT%H:%M:%S.%f")
        # Time delta in ms between two reads from stats endpoint
        delta_between_reads = total_milliseconds((read - preread))
        cpu_total = stats['cpu_stats']['cpu_usage']['total_usage']
        precpu_stats = stats['precpu_stats']
        precpu_total = precpu_stats['cpu_usage']['total_usage']
        cpu_delta = cpu_total - precpu_total
        number_of_periods = delta_between_reads / cpu_period
        total_quota = number_of_periods * cpu_quota
        # cpu delta is in nano seconds, convert to milliseconds
        quota_used_percent = 100 * cpu_delta / (total_quota * (10e5))
        emit(container,
             dimensions,
             'cpu.quota',
             [quota_used_percent],
             type_instance='used.percent',
             t=stats['read'])


# total_seconds() method of datetime available only from python 2.7
def total_milliseconds(td):
    td_microseconds = td.microseconds + \
                                ((td.seconds + td.days * 24 * 3600) * 10**6)
    td_milliseconds = td_microseconds / float(10**3)
    return td_milliseconds


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
                raise Exception('Unknown dimension provider {provider} '
                                'for dimension {dim}!'
                                .format(provider=provider, dim=name))

    def extract(self, client, container):
        dimensions = {}

        for name, spec in self._specs.items():
            provider, source = spec.split(':')
            value = None

            if provider == 'inspect' or provider == 'env':
                raw = client.inspect_container(container)
                env = {}
                raw_env = raw['Config']['Env'] or []
                for element in map(lambda e: e.split('=', 1), raw_env):
                    if len(element) == 2:
                        env[element[0]] = element[1]
                    elif len(element) == 1:
                        env[element[0]] = ""

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
        # Indicates whether the container stats has 'networks' information
        self.hasNetworks = True
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
                    self._feed = self._client.stats(self._container,
                                                    decode=True)
                self._stats = self._feed.next()

                # Reset failure count on successful read from the stats API.
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
            return self._stats
        return None


class DockerPlugin:
    """
    CollectD plugin for collecting statistics about running containers via
    Docker's remote API /<container>/stats endpoint.
    """

    DEFAULT_BASE_URL = 'unix://var/run/docker.sock'
    DEFAULT_DOCKER_TIMEOUT = 5

    # The new docker package only supports 1.21+.
    MIN_DOCKER_API_VERSION = '1.21'
    MIN_DOCKER_API_STRICT_VERSION = StrictVersion(MIN_DOCKER_API_VERSION)

    # TODO: add support for 'networks' from API >= 1.20 to get by-iface stats.
    METHODS = [read_network_stats, read_blkio_stats, read_cpu_stats,
               read_memory_stats]

    def __init__(self, docker_url=None):
        self.docker_url = docker_url or DockerPlugin.DEFAULT_BASE_URL
        self.timeout = DockerPlugin.DEFAULT_DOCKER_TIMEOUT
        self.capture = False
        self.dimensions = None
        self.excluded_labels = []
        self.excluded_images = []
        self.excluded_names = []
        self.stats = {}
        self.cpu_quota_bool = False
        self.cpu_shares_bool = False

    def is_excluded_label(self, container):
        """
        Determines whether container has labels and values matching the
        excluded label patterns
        """
        labels = container.get("Labels", {})
        for exlabel in self.excluded_labels:
            for label, value in labels.items():
                if exlabel[0].match(label) and exlabel[1].match(value):
                    log.info(("Excluding container '{c}' because the label "
                              "'{l}' matched pattern '{lreg}' and value '{v}' "
                              "matched pattern '{vreg}'"
                              ).format(c=container.get('Names', ''),
                                       l=label,
                                       lreg=exlabel[0].pattern,
                                       v=value,
                                       vreg=exlabel[1].pattern))
                    return True
        return False

    def is_excluded_image(self, container):
        """
        Determines whether container has image name matching the excluded
        image patterns
        """
        image = container.get("Image", "")
        for eximage in self.excluded_images:
            if eximage.match(image):
                log.info(("Excluding container '{c}' because the image name "
                          "'{img}' matched pattern '{eximg}'"
                          ).format(img=image, eximg=eximage.pattern,
                                   c=container.get('Names', '')))
                return True
        return False

    def is_excluded_name(self, container):
        """
        Determines whether container has a name matching the excluded
        name patterns
        """
        names = container.get("Names", [])
        for exname in self.excluded_names:
            for name in names:
                if exname.match(name):
                    log.info(("Excluding container '{c}' because the "
                              "container name '{n}' matched pattern '{exn}'"
                              ).format(n=name, exn=exname.pattern,
                                       c=container.get('Names', '')))
                    return True
        return False

    def is_excluded(self, container):
        """
        Determines whether the container should be excluded from metric
        collection based on image name, names, or labels
        """
        return self.is_excluded_image(container) \
            or self.is_excluded_name(container) \
            or self.is_excluded_label(container)

    def _container_name(self, names):
        """Extract the true container name from the list of container names
        sent back by the Docker API. The list of container names contains the
        names of linked containers too ('/other/alias' for example), but we're
        only interested in the true container's name, '/foo'. Also handle
        containers names when running on Docker Swarm: drop the unnecessary
        service ID, but keep instance number."""
        for name in names:
            slash_arr = name.split('/')
            if len(slash_arr) == 2:
                new_name = slash_arr[1]

                dot_arr = new_name.split('.')
                if len(dot_arr) > 2 and len(dot_arr[-1]) == 25:
                    new_name = '.'.join(dot_arr[0:-1])

                return new_name
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
                elif node.key == 'CpuQuotaPercent':
                    self.cpu_quota_bool = str_to_bool(node.values[0])
                elif node.key == 'CpuSharesPercent':
                    self.cpu_shares_bool = str_to_bool(node.values[0])
                elif (node.key == 'ExcludeName' or
                      node.key == 'ExcludeImage' or
                      node.key == 'ExcludeLabel'):
                    if len(node.values) >= 1:
                        pattern = node.values[0]
                        try:
                            reg = re.compile(pattern)
                            if node.key == 'ExcludeName':
                                self.excluded_names.append(reg)
                            elif node.key == 'ExcludeImage':
                                self.excluded_images.append(reg)
                            else:  # node.key == 'ExcludeLabel'
                                if len(node.values) == 2:
                                    pattern = node.values[1]
                                else:
                                    pattern = ".*"
                                val = re.compile(pattern)
                                self.excluded_labels.append([reg, val])
                        except Exception as e:
                            log.error('Failed to compile regex pattern "{p}". '
                                      'The following exclusion "{e}" with '
                                      'values "{v}" will be ignored.  Please '
                                      'fix the pattern'.format(p=pattern,
                                                               e=node.key,
                                                               v=node.values))

            except Exception as e:
                log.error('Failed to load the configuration %s due to %s'
                          % (node.key, e))
                raise e

        self.dimensions = DimensionsProvider(specs)

    def init_callback(self):
        self.client = docker.APIClient(
            base_url=self.docker_url,
            version=DockerPlugin.MIN_DOCKER_API_VERSION)
        self.client.timeout = self.timeout

        try:
            version = self.client.version()['ApiVersion']
        except IOError, e:
            # Log a warning if connection is not established
            collectd.warning((
                    'Unable to access Docker daemon at {url} in \
                    init_callback. Will try in read_callback.'
                    'This may indicate SELinux problems. : {error}')
                    .format(url=self.docker_url, error=e))

            collectd.register_read(
                    self.read_callback,
                    interval=COLLECTION_INTERVAL)

            return True

        # Check API version for stats endpoint support.
        if not self.check_version(version):
            return False

        collectd.register_read(self.read_callback,
                               interval=COLLECTION_INTERVAL)
        log.notice(('Collecting stats about Docker containers from {url} '
                    '(API version {version}; timeout: {timeout}s).')
                   .format(url=self.docker_url,
                           version=version,
                           timeout=self.timeout))
        return True

    # Method to compare docker version with min version required
    def check_version(self, version):
        if StrictVersion(version) < \
                DockerPlugin.MIN_DOCKER_API_STRICT_VERSION:
            log.error(('Docker daemon at {url} does not '
                       'support container statistics!')
                      .format(url=self.docker_url))
            return False
        return True

    def read_callback(self):
        try:
            version = self.client.version()['ApiVersion']
        except IOError, e:
            # Log a warning if connection is not established
            log.exception(('Unable to access Docker daemon at {url}. '
                           'This may indicate SELinux problems. : {error}')
                          .format(url=self.docker_url,
                                  error=e))
            return

        # Check API version for stats endpoint support.
        if not self.check_version(version):
            return

        try:
            containers = [c for c in self.client.containers()
                          if c['Status'].startswith('Up')]

            # Log the list of containers retrieved
            log.info('The following containers were fetched from {url}: '
                     '{c}'.format(url=self.docker_url, c=containers))
        except Exception as e:
            containers = []
            log.exception(('Failed to retrieve containers info from {url} '
                           'This may indicate that the Docker API is '
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

        containers_state = []
        for container in containers:
            try:
                container['Name'] = self._container_name(container['Names'])
                # Start a stats gathering thread if the container is new.
                if container['Id'] not in self.stats:
                    if self.is_excluded(container):
                        continue
                    self.stats[container['Id']] = \
                        ContainerStats(container, self.dimensions,
                                       self.client)

                cstats = self.stats[container['Id']]
                stats = cstats.stats if cstats else None
                read_at = stats.get('read') if stats else None
                if not read_at:
                    # No stats available yet; skipping container.
                    continue
                # Process stats through each reader.
                for method in self.METHODS:
                    try:
                        method(container, cstats.dimensions, stats, read_at)
                        # Reset hasNetworks if networks collects successfully
                        if method == read_network_stats and \
                           not cstats.hasNetworks:
                            cstats.hasNetworks = True
                    except Exception, e:
                        if method != read_network_stats or cstats.hasNetworks:
                            log.exception(('Unable to retrieve {method} stats '
                                           'for container {container}: {msg}')
                                          .format(
                                                method=method.__name__,
                                                container=_c(container),
                                                msg=e
                                         ))
                        if method == read_network_stats and cstats.hasNetworks:
                            cstats.hasNetworks = False

                # If CPU shares or quota metrics are required
                if self.cpu_shares_bool or self.cpu_quota_bool:
                    try:
                        # Get cgroup info container by inspecting the container
                        container_inspect = self.client \
                                                .inspect_container(container)
                        containers_state.append({
                                    'container': container,
                                    'container_inspect': container_inspect})
                    except Exception, e:
                        log.exception(('Unable to retrieve cpu share and quota'
                                       ' stats for {container}: {msg}').format(
                                           container=_c(container), msg=e))

            except Exception, e:
                log.exception(('Unable to retrieve stats for container '
                               '{container}: {msg}')
                              .format(container=_c(container), msg=e))
        if self.cpu_shares_bool:
            sum_of_shares = reduce(
                lambda a, b: a + (
                    b['container_inspect']['HostConfig']['CpuShares'] or 1024),
                containers_state,
                0)

        for state in containers_state:
            container = state['container']
            inspect = state['container_inspect']
            cstats = self.stats[container['Id']]
            cpu_percent = get_cpu_percent(cstats.stats)
            if self.cpu_quota_bool:
                read_cpu_quota_stats(container, inspect, cstats)
            if self.cpu_shares_bool:
                read_cpu_shares_stats(container,
                                      inspect,
                                      cstats,
                                      cpu_percent,
                                      sum_of_shares)

    def stop_all(self):
        for stat_thread in self.stats.values():
            stat_thread.stop = True


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
        Emits a log record to the appropriate collectd log function

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
                              'to: {e}').format(p=self.plugin, e=e))


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


def shutdown():
    """Cleanup on plugin shutdown."""
    log.info("dockerplugin shutting down")
    log.removeHandler(handle)

    plugin.stop_all()


# Set up logging
logging.setLoggerClass(CollectdLogger)
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.propagate = False
handle = CollectdLogHandler('docker')
log.addHandler(handle)

# Command-line execution
if __name__ == '__main__':
    class CollectdConfigurations():
        def __init__(self):
            self.children = []

        def __repr__(self):
            return str(self.__dict__)

    class Configuration():
        def __init__(self, key, values):
            self.key = key
            self.values = values

        def __repr__(self):
            return str(self.__dict__)

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

        def register_read(self, callback, interval):
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

    # importing here because collectd must be instantiated first in order to
    # log the import error
    try:
        import argparse
    except ImportError as e:
        raise Exception("Unable to import the library 'argparse'. "
                        "Please install the dependency argparse using pip.")

    plugin = DockerPlugin()

    # set up argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('--BaseURL', type=str,
                        help="specifies url used to interact with docker api")
    parser.add_argument('--Timeout', type=int,
                        help="specifies the timeout in seconds for requests")
    parser.add_argument('--Dimension', type=str, nargs='+', action='append',
                        help='specifies the <name> and <spec>')
    parser.add_argument('--Verbose', type=str,
                        help="turns verbose logging on or off (true/false)")
    parser.add_argument('--Interval', type=int,
                        help="sets interval for reporting metrics")
    parser.add_argument('--ExcludeLabel', type=str, nargs='+', action='append',
                        help="specifies a <label> and <value> regex patterns")
    parser.add_argument('--ExcludeName', type=str, nargs=1, action='append',
                        help="specifies a <name> regex pattern to filter by")
    parser.add_argument('--ExcludeImage', type=str, nargs=1, action='append',
                        help="specifies an <image name> pattern to filter by")
    args = parser.parse_args()

    # transform arguments into configurations
    configs = CollectdConfigurations()
    interval = COLLECTION_INTERVAL
    if args.BaseURL:
        configs.children.append(Configuration('BaseURL', [args.BaseURL]))
    if args.Timeout:
        configs.children.append(Configuration('Timeout',
                                              [str(args.Timeout)]))
    if args.Dimension:
        for elem in args.Dimension:
            configs.children.append(Configuration('Dimension', elem))
    if args.Verbose:
        configs.children.append(Configuration('Verbose', [args.Verbose]))
    if args.Interval:
        interval = args.Interval
        configs.children.append(Configuration('Interval',
                                              [str(interval)]))
    if args.ExcludeLabel:
        for elem in args.ExcludeLabel:
            configs.children.append(Configuration('ExcludeLabel', elem))
    if args.ExcludeName:
        for elem in args.ExcludeName:
            configs.children.append(Configuration('ExcludeName', elem))
    if args.ExcludeImage:
        for elem in args.ExcludeImage:
            configs.children.append(Configuration('ExcludeImage', elem))

    # pass configurations through collectd configuration code path
    plugin.configure_callback(configs)

    if not plugin.init_callback():
        sys.exit(1)

    while True:
        plugin.read_callback()
        time.sleep(interval)


# Normal plugin execution via CollectD
else:
    import collectd

    plugin = DockerPlugin()
    collectd.register_config(plugin.configure_callback)
    collectd.register_init(plugin.init_callback)
    collectd.register_shutdown(shutdown)
