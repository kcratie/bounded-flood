#!/bin/bash

systemctl mask getty@tty1.service && \
mkdir -p /opt/ipop-vpn && \
cd /opt/ipop-vpn && \
python3 -m venv ipop-venv  && \
source ipop-venv/bin/activate && \
pip3 --no-cache-dir install psutil==5.6.3 sleekxmpp==1.3.3 requests==2.21.0 simplejson==3.16.0 ryu==4.30 && \
deactivate
