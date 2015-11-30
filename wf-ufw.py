import tailer  # pip install tailer
import time
import pygrok  # pip install pygrok
import arrow  # pip install arrow
import logging

from tzlocal import get_localzone  # pip install tzlocal
from whitefacesdk.client import Client
from whitefacesdk.observable import Observable
from pprint import pprint

# this is a crappy work around for using python 2.7.6 that
# ships with Ubuntu 14.04. This is discuraged, see:
# http://urllib3.readthedocs.org/en/latest/security.html#disabling-warnings
import requests
requests.packages.urllib3.disable_warnings()

# whiteface settings
WHITEFACE_USER = ''
WHITEFACE_TOKEN = ''
WHITEFACE_FEED = ''

# check logs every X seconds (300 equals 5 minutes)
sleep_seconds = 300

# usually /var/log/ufw.log
filename = '/var/log/ufw.log'

# logging configuration
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s] - %(message)s'
logger = logging.getLogger(__name__)

# grok regular expressions for ufw logs
ufw_log_pattern = '%{SYSLOGTIMESTAMP:ufw_timestamp} %{SYSLOGHOST:ufw_hostname} %{DATA:ufw_program}(?:' \
                  '\[%{POSINT:ufw_pid}\])?: %{GREEDYDATA:ufw_message}'

ufw_message_pattern = '\[%{DATA}\] \[UFW %{WORD:ufw_action}\] IN=%{DATA:ufw_interface} OUT= MAC=%{DATA:ufw_mac} ' \
                      'SRC=%{IP:ufw_src_ip} DST=%{IP:ufw_dest_ip} %{GREEDYDATA:ufw_tcp_opts} ' \
                      'PROTO=%{WORD:ufw_protocol} SPT=%{INT:ufw_src_port} DPT=%{INT:ufw_dst_port} ' \
                      '%{GREEDYDATA:ufw_tcp_opts}'

ufw_tcp_opts_pattern = 'WINDOW=%{INT:ufw_tcp_window} RES=%{BASE16NUM:ufw_tcp_res} %{WORD:ufw_tcp_flag} ' \
                       'URGP=%{INT:ufw_tcp_urgp}'


def parse_record(line):
    """
    Parse a single ufw firewall log record using grok regular expressions and return a single dictionary

    :param line: single ufw firwall log record
    :return: dictionary
    """

    record = {}

    log_d = pygrok.grok_match(line, ufw_log_pattern)
    message_d = pygrok.grok_match(log_d['ufw_message'], ufw_message_pattern)
    tcp_opts_d = pygrok.grok_match(message_d['ufw_tcp_opts'], ufw_tcp_opts_pattern)

    # note: need to support python2.7.x here too ( log_d.items(), message_d.items() )
    for key, value in log_d.items():
        record[key] = value

    for key, value in message_d.items():
        record[key] = value

    for key, value in tcp_opts_d.items():
        record[key] = value

    return record


def normalize_syslog_timestamp(syslog_timestamp, time_now, local_tz):
    """
    Return a timestamp with the correct year and in UTC from a syslog timestamp
    :return: string (ex: 2015-11-11T21:15:29-0000)

    Reference:
    https://github.com/logstash-plugins/logstash-filter-date/pull/4/files
    https://github.com/jsvd/logstash-filter-date/blob/cfd8949e94ed0760434e3c9a9ff3da5351b4fd59/lib/logstash/filters/date.rb#L189
    """

    # get the current month
    now_month = time_now.month

    # semi normalize syslog timestamp
    syslog_timestamp_obj = arrow.get(syslog_timestamp, 'MMM DD HH:mm:ss')

    # get the month of the syslog timestamp
    event_month = syslog_timestamp_obj.month

    # calculate event year based on current month and event month
    if event_month == now_month:
        event_year = time_now.year
    elif event_month == 12 and now_month == 1:
        event_year = (time_now.year - 1)
    elif event_month == 1 and now_month == 12:
        event_year = (time_now.year + 1)
    else:
        event_year = time_now.year

    # update event year based on calculated result and local timezone
    syslog_timestamp_obj = syslog_timestamp_obj.replace(year=event_year, tzinfo=local_tz.zone)

    return syslog_timestamp_obj.to('UTC').format('YYYY-MM-DDTHH:mm:ssZ')


def process_events(events):
    """

    :param events: list - list of records from ufw.log
    :return [int] number of records sent
    """

    sent_count = 0

    # get local timezone
    local_tz = get_localzone()

    # Initiate wf client object
    cli = Client(token=WHITEFACE_TOKEN)

    # get now time object based on local timezone
    time_now = arrow.get(get_localzone())

    for line in events:
        record = parse_record(line)

        normalized_timestamp = normalize_syslog_timestamp(record['ufw_timestamp'], time_now, local_tz)

        if record['ufw_action'] == 'BLOCK':
            if record['ufw_protocol'] == 'TCP':
                if record['ufw_tcp_flag'] == 'SYN':
                    data = {
                        "user": WHITEFACE_USER,
                        "feed": WHITEFACE_FEED,
                        "observable": record['ufw_src_ip'],
                        "tags": "scanner",
                        "description": "sourced from firewall logs (incomming, TCP, Syn, blocked)",
                        "portlist": record['ufw_dst_port'],
                        "protocol": record['ufw_protocol'],
                        "lasttime": normalized_timestamp
                        }
                    try:
                        ret = Observable(cli, data).submit()
                        if ret['observable']['id']:
                            sent_count += 1
                    except Exception as e:
                        raise Exception(e)
    return sent_count


def main():

    # setup logging
    loglevel = logging.INFO
    console = logging.StreamHandler()
    logging.getLogger('').setLevel(loglevel)
    console.setFormatter(logging.Formatter(LOG_FORMAT))
    logging.getLogger('').addHandler(console)

    events = []
    for line in tailer.follow_path(filename):
        logger.info("looking for new ufw events")
        if line is not None:
            events.append(line)
        else:
            if events:
                sent_count = process_events(events)
                logger.info("sent {0} ufw events to whiteface".format(sent_count))
            time.sleep(sleep_seconds)
            events = []


if __name__ == '__main__':
    main()

