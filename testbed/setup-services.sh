#!/bin/bash

apt-get update
apt-get install -y openjdk-8-jdk
wget https://www.igniterealtime.org/downloadServlet?filename=openfire/openfire_4.4.1_all.deb \
  -O openfire_4.4.1_all.deb
apt-get install -y ./openfire_4.4.1_all.deb
git clone https://github.com/ipop-project/Network-Visualizer.git
cd Network-Visualizer/setup
./setup.sh
chown -R kcratie /users/kcratie/
