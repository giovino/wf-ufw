import tailer  # pip install tailer
import time
import arrow  # pip install arrow
import logging
import re

from tzlocal import get_localzone  # pip install tzlocal
from whitefacesdk.client import Client
from whitefacesdk.indicator import Indicator
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


def parse_record(line):
    """
    Parse a single ufw firewall log record using regular expressions and return a single dictionary

    :param line: single ufw firwall log record
    :return: dictionary
    """

    record = {}

    # parse of entire ufw log record
    log_l = re.split(r'\s+', line, 6)
    # set syslog time stamp
    record['ufw_timestamp'] = "{0} {1} {2}".format(log_l[0], log_l[1], log_l[2])
    # set hostname
    record['ufw_hostname'] = log_l[3]
    # set program
    record['ufw_program'] = log_l[4]
    # find pid
    m = re.match('\[(\S+)\]',log_l[5])
    # set pid
    record['ufw_pid'] = m.group(1)
    # set ufw message
    record['ufw_message'] = log_l[6]

    # parse ufw_message bits
    m = re.match('\[UFW\s(\S+)\]\s(.*)', record['ufw_message'])
    # set ufw action
    record['ufw_action'] = m.group(1)

    # continue parsing ufw_message
    _r1 = re.split(r'\s+', m.group(2), 3)

    # parse layer 2 items (in, out, mac)
    base = _r1[:-1]

    # parse string after base bits
    leftover = re.split(r'\s+', _r1[-1])

    #pprint(leftover)

    for item in base:
        if item.startswith('IN'):
            record['ufw_interface_in'] = _split_equal(item)
        elif item.startswith('OUT'):
            record['ufw_interface_out'] = _split_equal(item)
        elif item.startswith('MAC'):
            record['ufw_mac'] = _split_equal(item)

    #print(leftover)

    # iterate through a copy of the leftover list
    for item in leftover[:]:
        record['ufw_ip_flag_ce'] = 0
        record['ufw_ip_flag_df'] = 0
        record['ufw_ip_flag_mf'] = 0

        if item.startswith('SRC'):
            record['ufw_src_ip'] = _split_equal(item)
        elif item.startswith('DST'):
            record['ufw_dest_ip'] = _split_equal(item)
        elif item.startswith('LEN'):
            record['ufw_ip_len'] = _split_equal(item)
        elif item.startswith('TOS'):
            record['ufw_ip_tos'] = _split_equal(item)
        elif item.startswith('PREC'):
            record['ufw_ip_prec'] = _split_equal(item)
        elif item.startswith('TTL'):
            record['ufw_ip_ttl'] = _split_equal(item)
        elif item.startswith('ID'):
            record['ufw_ip_id'] = _split_equal(item)
        elif item == "CE":
            record['ufw_ip_flag_ce'] = 1
        elif item == "DF":
            record['ufw_ip_flag_df'] = 1
        elif item == "MF":
            record['ufw_ip_flag_mf'] = 1
        else:
            continue

        leftover.remove(item)

    # parse out protocols
    if leftover[0] == 'PROTO=TCP':
        record['ufw_protocol'] = 'TCP'
        record['ufw_tcp_flag_cwr'] = 0
        record['ufw_tcp_flag_ece'] = 0
        record['ufw_tcp_flag_urg'] = 0
        record['ufw_tcp_flag_ack'] = 0
        record['ufw_tcp_flag_psh'] = 0
        record['ufw_tcp_flag_rst'] = 0
        record['ufw_tcp_flag_syn'] = 0
        record['ufw_tcp_flag_fin'] = 0

        for item in leftover:
            if item.startswith('SPT'):
                record['ufw_src_port'] = _split_equal(item)
            elif item.startswith('DPT'):
                record['ufw_dst_port'] = _split_equal(item)
            elif item.startswith('WINDOW'):
                record['ufw_tcp_window'] = _split_equal(item)
            elif item.startswith('RES'):
                record['ufw_tcp_res'] = _split_equal(item)
            elif item.startswith('URGP'):
                record['ufw_tcp_urgp'] = _split_equal(item)
            elif item == "CWR":
                record['ufw_tcp_flag_cwr'] = 1
            elif item == "ECE":
                record['ufw_tcp_flag_ece'] = 1
            elif item == "URG":
                record['ufw_tcp_flag_urg'] = 1
            elif item == "ACK":
                record['ufw_tcp_flag_ack'] = 1
            elif item == "PSH":
                record['ufw_tcp_flag_psh'] = 1
            elif item == "RST":
                record['ufw_tcp_flag_rst'] = 1
            elif item == "SYN":
                record['ufw_tcp_flag_syn'] = 1
            elif item == "FIN":
                record['ufw_tcp_flag_fin'] = 1

    elif leftover[0] == 'PROTO=UDP':
        record['ufw_protocol'] = 'UDP'

        for item in leftover:
            if item.startswith('SPT'):
                record['ufw_src_port'] = _split_equal(item)
            elif item.startswith('DPT'):
                record['ufw_dst_port'] = _split_equal(item)
            elif item.startswith('LEN'):
                record['ufw_udp_len'] = _split_equal(item)

    elif leftover[0] == 'PROTO=ICMP':
        record['ufw_protocol'] = 'ICMP'

        for item in leftover:
            if item.startswith('TYPE'):
                record['ufw_icmp_type'] = _split_equal(item)
            elif item.startswith('CODE'):
                record['ufw_icmp_code'] = _split_equal(item)
            # need to parse out ICMP types of those are determined to be needed

    return record

def _split_equal(item):
    """
    This function takes in a value in teh form <key>=<value> and returns the value

    :param item: (eg: SRC=141.212.121.155)
    :return: value [str]
    """
    result = item.rsplit('=', 1)
    return result[1]


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
    syslog_timestamp_obj = arrow.get(syslog_timestamp, ['MMM  D HH:mm:ss', 'MMM D HH:mm:ss'])

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
                if record['ufw_tcp_flag_syn'] == 1:
                    data = {
                        "user": WHITEFACE_USER,
                        "feed": WHITEFACE_FEED,
                        "indicator": record['ufw_src_ip'],
                        "tags": "scanner",
                        "description": "sourced from firewall logs (incomming, TCP, Syn, blocked)",
                        "portlist": record['ufw_dst_port'],
                        "protocol": record['ufw_protocol'],
                        "lasttime": normalized_timestamp
                        }
                    try:
                        ret = Indicator(cli, data).submit()
                        if ret['indicator']['id']:
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
        if line is not None:
            events.append(line)
        else:
            if events:
                sent_count = process_events(events)
                logger.info("sent {0} ufw events to whiteface".format(sent_count))
            time.sleep(sleep_seconds)
            logger.info("looking for new ufw events")
            events = []


if __name__ == '__main__':
    main()

