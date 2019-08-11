#!/bin/bash
if [ -z `which pip` ]  ; then
   echo "Error: python-pip not install."
   exit 1 
fi

pip install --upgrade pip
if [ `ansible --version | head -1 | cut -f2 -d' '|cut -c1-3` != "2.7" ]; then
   echo "Error: The script only supports ansible 2.7."
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

echo "CloudEngine modules path:$ANSIBLE_PATH/modules/network/cloudengine"
mkdir -p $ANSIBLE_PATH/modules/network/cloudengine

echo "Copying files ..."
if [ -d "./library" ]; then
    cp -rf ./library/*.py $ANSIBLE_PATH/modules/network/cloudengine
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

echo "Updateing constants.py"
ce_exist=`cat $ANSIBLE_PATH/constants.py | grep "NETWORK_GROUP_MODULES"| grep "ce"`
if [ -z "$ce_exist" ]; then
    replace_line=`grep -rn "NETWORK_GROUP_MODULES" $ANSIBLE_PATH/constants.py  | cut -d ":" -f 1`
    if [ $replace_line ]; then
        sed -i "${replace_line}s/'nxos'/'nxos', 'ce'/g" $ANSIBLE_PATH/constants.py
    else
        echo "Update Updateing constants.py failed, NETWORK_GROUP_MODULES in constants.py should be manually updated."
    fi
fi

echo "CloudEngine Ansible 2.7 library installed."
