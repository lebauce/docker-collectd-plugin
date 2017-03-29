### CHANGELOG

This file documents important changes to the Docker plugin for collectd. 

- [2017-03-29: Improve Dimension Extraction Robustness](#2017-03-29)
- [2016-08-03: Dimensionalize block I/O and CPU per-core metrics](#2016-08-03)

#### <a name="2017-03-29">2017-03-29: Dimensionalize block I/O and CPU per-core metrics</a>

Improves the stability of the plugin when containers are observed with environment variables set to empty strings.

#### <a name="2016-08-03">2016-08-03: Dimensionalize block I/O and CPU per-core metrics</a>

Prior to this update, the plugin transmitted block I/O and CPU per-core metrics
with the names of the block device and CPU core respectively included as part of
the metric name. In this update, this information has been removed from metric
names to dimensions.

SignalFx's built-in dashboards have been updated to accommodate metrics from
both before and after this change. 

When you upgrade to this version, any custom SignalFx charts and detectors that
you have built that include block I/O or per-core CPU metrics may need to be
modified to include the new metric names. Modify charts as follows: 

1. Whenever a chart uses an affected metric (see below), add a new plot to the
chart that uses the new metric name instead. 
1. On the new plot, apply a filter by the new dimensions, with a value that 
matches the contents of the previous metric name.
1. If your chart uses a timeseries expression that refers to the previous metric,
clone the expression, then modify any letter references in the clone to refer to
the new plot instead of the old one. 

For detectors, follow the procedure above, then select the new plot or new
timeseries expression as the signal. 

##### Block I/0: blkio.io_service_bytes_recursive.*

In this update, the block device identifier has been moved from metric names
to the dimensions called "device_major" and "device_minor". 

For example: 

|        | Metric name | device_major | device_minor |
|--------|-------------|--------------|--------------|
| Before | `blkio.io_service_bytes_recursive-252-0.read` | _n/a_ | _n/a_ |
| After  | `blkio.io_service_bytes_recursive.read` | `252` | `0` |


##### CPU statistics per core: cpu.percpu.usage

In this update, the CPU core identifier has been moved from metric names to
the dimension called "core". 

For example: 

|        | Metric name | core |
|--------|-------------|--------------|
| Before | `cpu.percpu.usage.cpu0` | _n/a_ |
| After  | `cpu.percpu.usage` | `cpu0` |
