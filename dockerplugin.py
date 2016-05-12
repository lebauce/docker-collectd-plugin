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

from distutils.version import StrictVersion
import docker
import os
import threading
import Queue
import time
import sys
import re

STREAM_DOCKER_PY_VERSION = (1, 6, 0)

c_stats = {}


def _c(c):
    """A helper method for representing a container in messages. If the given
    argument is a string, it is assumed to be the container's ID and only the
    first 7 digits will be returned. If it's a dictionary, the string returned
    is <7-digit ID>/<name>."""
    if type(c) == str or type(c) == unicode:
        return c[:7]
    return '{id}/{name}'.format(id=c['Id'][:7], name=c['Name'])


class Stats:
    @classmethod
    def emit(cls, container, type, value, t=None, type_instance=None):
        val = collectd.Values()
        val.plugin = 'docker'
        val.plugin_instance = container['Name']

        if type:
            val.type = type
        if type_instance:
            val.type_instance = type_instance

        if t:
            val.time = time.mktime(dateutil.parser.parse(t).timetuple())
        else:
            val.time = time.time()

        # With some versions of CollectD, a dummy metadata map must to be added
        # to each value for it to be correctly serialized to JSON by the
        # write_http plugin. See
        # https://github.com/collectd/collectd/issues/716
        val.meta = {'true': 'true'}

        val.values = value
        val.dispatch()

    @classmethod
    def read(cls, container, stats, t):
        raise NotImplementedError


class BlkioStats(Stats):
    @classmethod
    def read(cls, container, stats, t):
        blkio_stats = stats['blkio_stats']
        for key, values in blkio_stats.items():
            # Block IO stats are reported by block device (with major/minor
            # numbers). We need to group and report the stats of each block
            # device independently.
            device_stats = {}
            for value in values:
                k = '{key}-{major}-{minor}'.format(key=key,
                                                   major=value['major'],
                                                   minor=value['minor'])
                if k not in device_stats:
                    device_stats[k] = []
                device_stats[k].append(value['value'])

            for type_instance, values in device_stats.items():
                if len(values) == 5:
                    cls.emit(container, 'blkio', values,
                             type_instance=type_instance, t=t)
                elif len(values) == 1:
                    # For some reason, some fields contains only one value and
                    # the 'op' field is empty. Need to investigate this
                    cls.emit(container, 'blkio.single', values,
                             type_instance=key, t=t)
                else:
                    collectd.warn(('Unexpected number of blkio stats for '
                                   'container {container}!')
                                  .format(container=_c(container)))


class CpuStats(Stats):
    @classmethod
    def read(cls, container, stats, t):
        cpu_stats = stats['cpu_stats']
        cpu_usage = cpu_stats['cpu_usage']

        percpu = cpu_usage['percpu_usage']
        for cpu, value in enumerate(percpu):
            cls.emit(container, 'cpu.percpu.usage', [value],
                     type_instance='cpu%d' % (cpu,), t=t)

        items = sorted(cpu_stats['throttling_data'].items())
        cls.emit(container, 'cpu.throttling_data', [x[1] for x in items], t=t)

        system_cpu_usage = cpu_stats['system_cpu_usage']
        values = [cpu_usage['total_usage'], cpu_usage['usage_in_kernelmode'],
                  cpu_usage['usage_in_usermode'], system_cpu_usage]
        cls.emit(container, 'cpu.usage', values, t=t)

        # CPU Percentage based on calculateCPUPercent Docker method
        # https://github.com/docker/docker/blob/master/api/client/stats.go
        cpu_percent = 0.0
        if 'precpu_stats' in stats:
            precpu_stats = stats['precpu_stats']
            precpu_usage = precpu_stats['cpu_usage']
            cpu_delta = cpu_usage['total_usage'] - precpu_usage['total_usage']
            system_delta = system_cpu_usage - precpu_stats['system_cpu_usage']
            if system_delta > 0 and cpu_delta > 0:
                cpu_percent = 100.0 * cpu_delta / system_delta * len(percpu)
        cls.emit(container, "cpu.percent", ["%.2f" % (cpu_percent)], t=t)


class NetworkStats(Stats):
    @classmethod
    def read(cls, container, stats, t):
        items = sorted(stats['network'].items())
        cls.emit(container, 'network.usage', [x[1] for x in items], t=t)


class MemoryStats(Stats):
    @classmethod
    def read(cls, container, stats, t):
        mem_stats = stats['memory_stats']
        values = [mem_stats['limit'], mem_stats['max_usage'],
                  mem_stats['usage']]
        cls.emit(container, 'memory.usage', values, t=t)

        for key, value in mem_stats['stats'].items():
            cls.emit(container, 'memory.stats', [value],
                     type_instance=key, t=t)

        mem_percent = 100.0 * mem_stats['usage'] / mem_stats['limit']
        cls.emit(container, 'memory.percent', ["%.2f" % mem_percent], t=t)


class ReadContainerStats(threading.Thread):
    '''
    A worker that continuously pop container out of a Queue and query stats
    from the Docker Api, then store the result in a python dict
    We need this class to be sure that we will read all containers stats without
    overloading the docker deaemon.
    '''
    def __init__(self, client, stream, queue, _id):
        threading.Thread.__init__(self)
        self.daemon = True
        self.stop = False
        self.name = "Worker %d" % _id

        self._client = client
        self._stream = stream
        self._queue = queue

        self.start()

    def run(self):
        collectd.info('Starting stats gathering %s.' % self.name)
        while not self.stop:
            container = self._queue.get()
            try:
                if not self._stream:
                    stats = self._client.stats(container,
                                               decode=True)
                    c_stats[container['Id']] = stats._feed.next()
                else:
                    c_stats[container['Id']] = self._client.stats(container,
                                                                  decode=True, stream=False)
            except Exception, e:
                collectd.warning('Error reading stats from {container}: {msg}'
                                 .format(container=_c(container), msg=e))
        collectd.info('Stopped stats gathering for %s.' % self.name)


class DockerPlugin:
    """
    CollectD plugin for collecting statistics about running containers via
    Docker's remote API /<container>/stats endpoint.
    """

    DEFAULT_BASE_URL = 'unix://var/run/docker.sock'
    DEFAULT_DOCKER_TIMEOUT = 5

    # The stats endpoint is only supported by API >= 1.17
    MIN_DOCKER_API_VERSION = '1.17'

    CLASSES = [NetworkStats, BlkioStats, CpuStats, MemoryStats]

    def __init__(self, docker_url=None):
        self.docker_url = docker_url or DockerPlugin.DEFAULT_BASE_URL
        self.timeout = DockerPlugin.DEFAULT_DOCKER_TIMEOUT
        self.capture = False
        self.stats = {}
        self.stream = False
        self.rate_limit = 5
        self.queue = Queue.Queue()
        self.workers = []
        s_version = re.match('([\d.]+)', docker.__version__)
        version = tuple([int(x) for x in s_version.group(1).split('.')])
        if version >= STREAM_DOCKER_PY_VERSION:
            self.stream = True
            collectd.info('Docker stats use stream')

    def configure_callback(self, conf):
        for node in conf.children:
            if node.key == 'BaseURL':
                self.docker_url = node.values[0]
            elif node.key == 'RateLimit':
                self.rate_limit = int(node.values[0])
            elif node.key == 'Timeout':
                self.timeout = int(node.values[0])

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
            collectd.warning(('Docker daemon at {url} does not '
                              'support container statistics!')
                             .format(url=self.docker_url))
            return False

        collectd.register_read(self.read_callback)
        collectd.info(('Collecting stats about Docker containers from {url} '
                       '(API version {version}; timeout: {timeout}s).')
                      .format(url=self.docker_url,
                              version=version,
                              timeout=self.timeout))
        collectd.info("Rate limit for Docker API is %d" % self.rate_limit)

        for i in (range(self.rate_limit)):
            worker = ReadContainerStats(self.client, self.stream, self.queue, i)
            self.workers.append(worker)
        return True

    def read_callback(self):

        containers = [c for c in self.client.containers()
                      if c['Status'].startswith('Up')]

        # Remove useless stats from dead container
        for cid in set(c_stats) - set(map(lambda c: c['Id'], containers)):
            try:
                del c_stats[cid]
            except Exception:
                None

        queue = True
        qsize = self.queue.qsize()
        if qsize > len(containers):
            queue = False
            collectd.warning(('WARNING: The current queue size is bigger than the number of'
                              'containers, considering increment the RateLimit in collectd.conf'
                              '( Queue size = {qsize} for {len} containers')
                             .format(qsize=qsize, len=len(containers)))

        for container in containers:
            try:
                for name in container['Names']:
                    # Containers can be linked and the container name is not
                    # necessarly the first entry of the list
                    if not re.match("/.*/", name):
                        container['Name'] = name[1:]

                if queue:
                    self.queue.put(container)

                if container['Id'] in c_stats:
                    stats = c_stats[container['Id']]
                    if stats:
                        t = stats['read']
                        for klass in self.CLASSES:
                            klass.read(container, stats, t)
            except Exception, e:
                collectd.warning(('Error getting stats for container '
                                  '{container}: {msg}')
                                 .format(container=_c(container), msg=e))


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

        def warning(self, msg):
            print 'WARNING:', msg

        def info(self, msg):
            print 'INFO:', msg

        def register_read(self, docker_plugin):
            pass

    collectd = ExecCollectd()
    plugin = DockerPlugin()
    if len(sys.argv) > 1:
        plugin.docker_url = sys.argv[1]

    if plugin.init_callback():
        plugin.read_callback()

# Normal plugin execution via CollectD
else:
    import collectd
    plugin = DockerPlugin()
    collectd.register_config(plugin.configure_callback)
    collectd.register_init(plugin.init_callback)
