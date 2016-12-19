## ABOUT

Huawei CloudEngine Switch support for using Ansible to deploy devices. The Huawei CloudEngine Ansible library, enables you to use Ansible to perform specific operational and configuration tasks on CloudEngine devices.

## OVERVIEW OF MODULES

- aaa | ce_aaa_server - Manages AAA server global configuration
- aaa | ce_aaa_server_host - Manages AAA server host-specific configuration
- bgp | ce_bgp - Manages BGP configuration
- bgp | ce_bgp_af - Manages BGP Address-family configuration
- bgp | ce_bgp_neighbor - Manages BGP neighbors configurations
- bgp | ce_bgp_neighbor_af - Manages BGP address-family’s neighbors configuration
- command | ce_command - Run arbitrary command on Huawei CloudEngine devices
- config | ce_config - Manage Huawei CloudEngine configuration sections
- facts | ce_facts - Gets facts about Huawei CloudEngine switches
- interface | ce_interface - Manages physical attributes of interfaces
- interface | ce_mtu - Manages MTU settings on CloudEngine switch
- interface | ce_ip_interface - Manages L3 attributes for IPv4 and IPv6 interfaces
- interface | ce_interface_ospf - Manages configuration of an OSPF interface instance
- L2 | ce_vlan - Manages VLAN resources and attributes
- L2 | ce_switchport - Manages Layer 2 switchport interfaces
- L2 | ce_eth_trunk - Manages ethernet trunk attributes of interfaces
- L3 | ce_static_route - Manages static route configuration
- netconf | ce_netconf - To execute netconf RPC on Huawei CloudEngine devices and save output locally
- ntp | ce_ntp - Manages - Manages core NTP configuration
- ntp | ce_ntp_auth - Manages NTP authentication
- ospf | ce_ospf - Manages configuration of an ospf instance

## INSTALLATION

Circumstance instruction:
Ansible network module is suitable for ansible version 2.2. The available ncclient version is 0.5.2.

Main steps:

Install suitable Ansible master
Install suitable ncclient library
Install Huawei Ansible library

## EXAMPLE USAGE
An example of static manifest for CloudEngine switch is followed. The network functions is satisfied based on the assumed that Ansible moudle is available.
```
root@localhost:~# ansible -m ce_command -a "commands='display vlan summary' transport='cli' host=192.168.1.1 port=22 username=huawei password=huawei123" localhost --connection local
localhost | SUCCESS => {
    "changed": false, 
    "stdout": [
        "Number of static VLAN: 3\nVLAN ID: 1 4001 to 4002 \n\nNumber of dynamic VLAN: 0\nVLAN ID: \n\nNumber of service VLAN: 62\nVLAN ID: 4030 to 4060 4064 to 4094 "
    ], 
    "stdout_lines": [
        [
            "Number of static VLAN: 3", 
            "VLAN ID: 1 4001 to 4002 ", 
            "", 
            "Number of dynamic VLAN: 0", 
            "VLAN ID: ", 
            "", 
            "Number of service VLAN: 62", 
            "VLAN ID: 4030 to 4060 4064 to 4094 "
        ]
    ], 
    "warnings": []
}
```

## DEPENDENCIES

Thes modules require the following to be installed on the Ansible server:

* Python 2.6 or 2.7
* [Ansible](http://www.ansible.com) 2.2 or later
* [ncclient](https://github.com/ncclient/ncclient) 0.5.2 or later
* [Huawei support](http://www.huawei.com/en/)
