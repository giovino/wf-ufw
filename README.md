# wf-ufw
A script to sumbit blocked firewall events seen in ufw logs to whiteface

## Goals

1. To demonstrate how to interact with Whiteface using the Whiteface SDK

## Requirements

### Python modules

1. arrow
1. tzlocal
1. py-whitefacesdk
1. pytailer
1. supervisor

### Whiteface credentials

1. A [Whiteface](https://whiteface.csirtgadgets.com) account
1. A Whiteface account token; within Whiteface:
  1. Select your username
  1. Select "tokens"
  1. Select "Generate Token
1. A Whiteface feed; within Whiteface
  1. Select (the plus sign)
  1. Select Feed
  1. Choose a feed name (e.g. port scanners)
  1. Choose a feed description (hosts blocked in firewall logs)

### Linux

1. A Linux server with a public IP address
1. UFW installed and logging enabled

## Install

1. Create a directory for this project 

  ```bash
  mkdir -p /root/bin/wf-ufw
  cd /root/bin/wf-ufw
  ```
1. Download the wf-ufw.py script

  ```bash 
  wget https://raw.githubusercontent.com/giovino/wf-ufw/master/wf-ufw.py
  ```
1. Create a Python virtual environment

  ```bash
  virtualenv venv
  source venv/bin/activate
  ```
1. Upgrade and install packages

  ```bash
  pip install pip --upgrade
  pip install arrow tzlocal supervisor
  pip install https://github.com/csirtgadgets/py-whitefacesdk/archive/master.tar.gz 
  pip install https://github.com/GreatFruitOmsk/pytailer/archive/master.tar.gz
  ```
1. Edit wf-ufw.py to fill in (WHITEFACE_USER, WHITEFACE_FEED, WHITEFACE_TOKEN)

  ```bash
  vim wf-ufw.py
  ```

1. create a supervisord config

  ```bash
  echo_supervisord_conf > /etc/supervisord.conf
  ```
1. edit the supervisord config

  ```bash
  vim /etc/supervisord.conf
  ```
  add:
  ```bash
  [program:wf_ufw]
  command=/root/bin/wf-ufw/venv/bin/python2.7 /root/bin/wf-ufw/wf-ufw.py
  autostart=true
  autorestart=true
  stderr_logfile=/root/bin/wf-ufw/long.err.log
  stdout_logfile=/root/bin/wf-ufw/long.out.log
  ```
1. start supervisord

  ```bash
  supervisord -c /etc/supervisord.conf
  ```
1. tail /root/bin/wf-ufw/long.err.log to see it "working"

  ```bash
  $ tail -f /root/bin/wf-ufw/long.err.log

  2015-12-02 21:33:38,716 - INFO - __main__[288] - looking for new ufw events
  2015-12-02 21:33:38,732 - INFO - requests.packages.urllib3.connectionpool[735] - Starting new HTTPS connection (1): whiteface.csirtgadgets.com
  2015-12-02 21:33:38,942 - INFO - __main__[286] - sent 2 ufw events to whiteface
  ```

