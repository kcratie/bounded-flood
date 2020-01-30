#!/bin/bash

exp_dir=~/workspace/experiment

function prereqs
{
  sudo bash -c "
    apt-get update -y && \
    apt-get install -y openvswitch-switch=2.9.2-0ubuntu0.18.04.3 \
                        python3.6 python3-pip python3-venv \
                        apt-transport-https \
                        ca-certificates \
                        curl git \
                        software-properties-common && \

    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    add-apt-repository \"deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable\" && \
    apt-cache policy docker-ce && \
    apt-get install -y containerd.io=1.2.6-3 \
                       docker-ce-cli=5:18.09.7~3-0~ubuntu-bionic \
                       docker-ce=5:18.09.7~3-0~ubuntu-bionic && \
    groupadd -f docker && \
    echo $user_name && \
    usermod -a -G docker $USER \
  "
}

function venv
{
  cd $exp_dir
  python3 -m venv exp-venv
  source exp-venv/bin/activate
  pip3 install simplejson==3.16.0
}

function img
{
  cd $exp_dir
  docker rmi kcratie/bounded-flood:0.3
  docker build -f docker/ipop.Dockerfile -t kcratie/bounded-flood:0.3 ./docker
}

case $1 in
  prereqs)
    prereqs
    ;;
  venv)
    venv
    ;;
  img)
    img
    ;;
  *)
    echo "no match on input -> $1"
    ;;
esac
