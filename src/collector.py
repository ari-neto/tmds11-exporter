import time
from prometheus_client.core import GaugeMetricFamily, REGISTRY, CounterMetricFamily, Counter
from prometheus_client import start_http_server
from envparse import env
import logging
import signal
import sys
import config
import client_tm_ds as ds
from datetime import datetime

# Logging configuration
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=config.LOG_LEVEL)

server_port = env.str('SERVER_PORT', default=config.SERVER_PORT)
# max valid period of api retrieved data - in seconds
ds_api_check = env.str('DS_API_INTERVAL', default=config.DS_API_CHECK)
sleep = 15

def get_ds_summary(var=None):
    for key, value in var.items():
        # print('**key: {} - value: {}'.format(key, value))
        # print(key)
        if key != 'timestamp':
            # print(var[key])
            for k, val in var[key].items():
                print('{} - key: {} - value: {}'.format(key, k, val))

# https://github.com/jakirpatel/prometheus-custom-collector/blob/master/code/collector.py
class CustomCollector(object):
    def __init__(self):
        pass

    def collect(self):
        
        ds_metrics = ds.get_summary(ds_api_check)
        
        tm_ds_computers = CounterMetricFamily('deep_security_computers', 'Deep Security Computer Metrics', labels=[
            'metric', 'type', 'platform', 'status'])

        tm_ds_modules = CounterMetricFamily('deep_security_modules', 'Deep Security Modules Metrics', labels=[
            'metric', 'type', 'platform', 'status'])

        tm_ds_vulnerabilities = CounterMetricFamily('deep_security_vulnerabilities', 'Deep Security Vulnerabilities Metrics', labels=[
            'metric', 'type', 'platform', 'status','mode'])

        # get_ds_summary(ds_metrics)
        for key, value in ds_metrics.items():
            if key != 'timestamp':
                # print(var[key])
                for k, val in ds_metrics[key].items():
                    # print('{} - key: {} - value: {}'.format(key, k, val))
 
                    if k.split('-')[2] == 'all':
                        os_platform = k.split('-')[2]
                    else:
                        os_platform = k.split('-')[2].split('_')[1]
                    if k.split('-')[0] == 'computer':
                        # computer-os_type-os_linux-12.0.0.563-off - value: 1
                        # print('printing.... {},{},{},{}'.format(k.split('-')[1], key, os_platform, k.split('-')[3], int(val)))
                        tm_ds_computers.add_metric(
                            [k.split('-')[1], key, os_platform, k.split('-')[3]], int(val))
                    elif k.split('-')[0] == 'module':
                        # module-am_status-os_windows-on
                        tm_ds_modules.add_metric(
                            [k.split('-')[1], key, os_platform, k.split('-')[3]], int(val))

                    elif k.split('-')[0] == 'vulnerabilities':
                        # vulnerabilities-ips-os_windows-inline-tap - value: 2
                        tm_ds_vulnerabilities.add_metric(
                            [k.split('-')[1], key, os_platform, k.split('-')[3], k.split('-')[4]], int(val))
                        # if key == 'critical':
                        #     print('vul: {} - {} - {} - {} -{} - {}'.format(k.split('-')[1], key, os_platform, k.split('-')[3], k.split('-')[4], int(val)))
        yield tm_ds_computers
        yield tm_ds_modules
        yield tm_ds_vulnerabilities


def shutdown_app(signal_number, frame):
    """
    this function will process the term signal that will sent by k8s
    """
    try:
        logging.info('we received signal {}. we are shutting now!'.format(signal_number))
        sys.exit(0)
    except Exception as e:
        logging.info('error to shut down app: {}'.format(e))


def main():
    signal.signal(signal.SIGTERM, shutdown_app)
    signal.signal(signal.SIGINT, shutdown_app)
    # signal.signal(signal.SIGHUP, reload_app)
    start_http_server(server_port)
    while True:
        time.sleep(sleep)


if __name__ == '__main__':
    ds_collector = CustomCollector()
    REGISTRY.register(ds_collector)
    main()

