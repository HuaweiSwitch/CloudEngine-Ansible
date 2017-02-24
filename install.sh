#!/bin/bash
if [ -z `which pip` ]  ; then
   echo "Error: python-pip not install."
   exit 1 
fi

if [ `ansible --version | head -1 | cut -f2 -d' '|cut -c1-3` != "2.2" ]; then
   echo "Error: The script only supports ansible 2.2."
   exit 1
fi

ANSIBLE_LOCATION=`pip show ansible | grep Location | cut -f2 -d':'`
ANSIBLE_PATH="$ANSIBLE_LOCATION/ansible"

if [ -z "$ANSIBLE_LOCATION" ] ; then
    echo "Error: Can not get Ansible dist-packages location."
    exit 1
else
    echo "Ansible dist-packages path:$ANSIBLE_PATH"
fi

echo "CloudEngine modules path:$ANSIBLE_PATH/modules/core/network/cloudengine"
mkdir -p $ANSIBLE_PATH/modules/core/network/cloudengine

echo "Copying files ..."
if [ -d "./library" ]; then
    cp -rf ./library/*.py $ANSIBLE_PATH/modules/core/network/cloudengine
fi

if [ -d "./plugins" ]; then
    cp -rf ./plugins/* $ANSIBLE_PATH/plugins
fi

if [ -d "./utils" ]; then
    cp -rf ./utils/* $ANSIBLE_PATH/utils
fi

if [ -d "./module_utils" ]; then
    cp -rf ./module_utils/* $ANSIBLE_PATH/module_utils
fi

echo "CloudEngine Ansible library installed."
