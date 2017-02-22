This document translates the configuration of CE switches into YML scripts. After the symbol # is the CE switch configuration, followed by the configuration of the corresponding script.
```
# vlan batch 2 to 100 
# vlan 3000
  - name: "vlan 2 to 100"
    ce_vlan: vlan_range="2-100" state=present host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data
    
    - name: "vlan 3000"
    ce_vlan: vlan_id="3000" state=present host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

#assign forward nvo3 acl extend enable
#assign forward nvo3 eth-trunk hash enable
#assign forward nvo3 service extend enable
#assign forward nvo3-gateway enhanced  l3 
  - name: "assign forward nvo3"
    ce_vxlan_global: nvo3_service_extend=enable nvo3_eth_trunk_hash=disable nvo3_acl_extend=enable nvo3_gw_enhanced=l3 host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data
    
#dfs-group 1
#source ip 50.50.50.4
#active-active-gateway
#peer 50.50.50.1
#peer 50.50.50.2
#peer 50.50.50.3
  - name: "dfs-group 1"
    ce_vxlan_gateway: dfs_id=1 dfs_source_ip=50.50.50.4 dfs_all_active=enable dfs_peer_ip={{item.ip}} host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data
    with_items:
      - { ip: '50.50.50.1'}
      - { ip: '50.50.50.2'}
      - { ip: '50.50.50.3'}

#stp enable        
  - name: "stp"
    ce_stp: stp_enable=disable host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data
    
#ip vpn-instance vrf=alibaba-poap
#ipv4-family
#route-distinguisher 2007:1
  - name: "vpn-instance 1"
    ce_vrf: vrf=alibaba-poap host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

  - name: "vpn-instance 2"
    ce_vrf_af: vrf=alibaba-poap vrf_aftype=v4 route_distinguisher=2007:1 host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data
    
#bridge-domain 10001
#vxlan vni 10001
  - name: "create bridge-domain 10001"
    ce_vxlan_global: bridge_domain_id=10001  host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

  - name: "bridge-domain 10001"
    ce_vxlan_tunnel: bridge_domain_id=10001 vni_id=10001 host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

#bridge-domain 11000
#vxlan vni 11000  
  - name: "create bridge-domain 11000"
    ce_vxlan_global: bridge_domain_id=11000  host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

  - name: "bridge-domain 11000"
    ce_vxlan_tunnel: bridge_domain_id=11000 vni_id=11000 host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

#interface Vbdif10001
#ip address 93.0.0.1 255.0.0.0
#mac-address 0000-5e00-0101
  - name: "create interface vbdif 10001"
    ce_interface: interface='Vbdif10001' host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data 

  - name: "interface vbdif 10001"
    ce_ip_interface: interface='Vbdif10001' version=v4 addr=93.0.0.1 mask=8 host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

  - name: "add mac-address in interface vbdif 10001"
    ce_vxlan_gateway: vbdif_name='Vbdif10001' vbdif_mac='0000-5e00-0101' host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data	

#interface Vbdif11000
#ip address 17.207.1.1 255.255.255.0
#mac-address 0000-5e00-0101
  - name: "create interface vbdif 11000"
    ce_interface: interface='Vbdif11000' host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data 

  - name: "interface vbdif 11000"
    ce_ip_interface: interface='Vbdif11000' version=v4 addr=17.207.1.1 mask=24 host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

  - name: "add mac-address in interface vbdif 11000"
    ce_vxlan_gateway: vbdif_name='Vbdif11000' vbdif_mac='0000-5e00-0101' host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

#acl 2001
#rule 1 permit source 10.137.0.0 0.0.255.255	
  - name: "acl 2001 rule 1"
    ce_acl: acl_name=2001  rule_id=1  rule_action=permit source_ip=10.137.0.0 src_mask=16 host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data
#acl 2001
#rule 2 permit source 10.107.0.0 0.0.255.255
  - name: "acl 2001 rule 2"
    ce_acl: acl_name=2001  rule_id=2  rule_action=permit source_ip=100.107.0.0 src_mask=16 host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

#acl 3001
#rule 5 permit ip source 100.33.1.2 0 destination 194.85.1.2 0
  - name: "acl 3001 rule 5"
    ce_acl_advance: acl_name=3001 rule_id=5 rule_action=permit protocol=ip source_ip=100.33.1.2 src_mask=32 dest_ip=194.85.1.2 dest_mask=32 host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

#acl 3678
#rule 5 permit ip source 10.143.1.111 0 10.151.240.196 0
  - name: "acl 3678 rule 5"
    ce_acl_advance: acl_name=3678 rule_id=5 rule_action=permit protocol=ip source_ip=10.143.1.111 src_mask=32 dest_ip=10.151.240.196 dest_mask=32 host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data 

#interface 40GE1/0/9.3 mode l2
#encapsulation dot1q vid 100
#bridge-domain 11000
  - name: "create interface 40GE1/0/9.3 mode l2"
    ce_interface: interface='40GE1/0/9.3' l2sub=true host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data 

  - name: "add BD in interface 40GE1/0/9.3"
    ce_vxlan_vap: bridge_domain_id=11000 l2_sub_interface='40GE1/0/9.3' host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data 

  - name: "add encapsulation in interface 40GE1/0/9.3"
    ce_vxlan_vap: l2_sub_interface='40GE1/0/9.3' encapsulation=dot1q ce_vid=100 host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

#interface 40GE1/0/20.10
#ip address 101.203.100.1 255.255.255.0
  - name: "create interface 40GE1/0/20.10"
    ce_interface: interface='40GE1/0/20.10' host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

  - name: "add ip in interface 40GE1/0/20.10"
    ce_ip_interface: interface='40GE1/0/20.10' mode=layer3 version=v4 addr=101.203.100.1 mask=24 host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

#interface Nve1
#source ip 16.1.1.204
#vni 11000 head-end peer-list 64.210.4.2
#vni 11000 head-end peer-list 64.210.4.3
#vni 11000 head-end peer-list 64.210.4.4
#vni 11000 head-end peer-list 64.210.4.5
#vni 11000 head-end peer-list 64.210.4.6
#vni 11000 head-end peer-list 64.210.4.7
#vni 11000 head-end peer-list 64.210.4.8
#vni 11000 head-end peer-list 64.210.4.9
#vni 11000 head-end peer-list 64.210.4.10
  - name: "create interface Nve1"
    ce_interface: interface='Nve1' host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

  - name: "add source ip in interface Nve1"
    ce_vxlan_tunnel: nve_name=Nve1 source_ip=16.1.1.204  host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data

  - name: "add vni in interface Nve1"
    ce_vxlan_tunnel: nve_name=Nve1 vni_id=11000 peer_list_ip={{item.ip}}  host={{inventory_hostname}} port={{ansible_ssh_port}} username={{username}} password={{password}}
    register: data
    with_items:
      - { ip: '64.210.4.2'}
      - { ip: '64.210.4.3'}
      - { ip: '64.210.4.4'}       
      - { ip: '64.210.4.5'}      
      - { ip: '64.210.4.6'}  
      - { ip: '64.210.4.7'}
      - { ip: '64.210.4.8'}
      - { ip: '64.210.4.9'}
      - { ip: '64.210.4.10'}

#netstream top-talkers wu1 ip
#starting time 00:00:00 2015-01-01
#netstream timeout ip tcp-session
#netstream mpls-aware label-and-ip ip
#netstream export ip version 5 peer-as
#netstream export ip source 100.68.134.1
  - name: "netstream top-talkers"
    ce_config: lines='netstream top-talkers wu1 ip, starting time 00:00:00 2015-01-01' match=none host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "netstream timeout ip tcp-session"
    ce_netstream_aging: timeout_type=tcp-session type=ip state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "netstream mpls-aware label-and-ip ip"
    ce_config: lines='netstream mpls-aware label-and-ip ip' match=none host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "netstream export ip version"
    ce_netstream_export: type=ip version=5 as_option=peer host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "netstream export ip source"
    ce_netstream_export: type=ip source_ip=100.68.134.1 host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    
#snmp-agent community read commaccesss1
#snmp-agent community read commaccesss2
  - name: "snmp-agent community read"
    ce_snmp_community: access_right=read community_name=commaccesss1 host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "snmp-agent community read"
    ce_snmp_community: access_right=read community_name=commaccesss2 host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

#snmp-agent community write commaccesss1
  - name: "snmp-agent community write"
    ce_snmp_community: access_right=write community_name=commaccesss1 host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

#snmp-agent sys-info version all
  - name: "snmp-agent sys-info version all"
    ce_snmp_target_host: version=all host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}} state=absent
    register: data

#snmp-agent target-host host-name ACController trap address udp-domain 192.108.70.2 udp-port 1666 params securityname ACTrapUser v3 privacy private-netmanager
  - name: "snmp-agent target-host host-name"
    ce_snmp_target_host: host_name=ACController address=192.108.70.2 notify_type=trap recv_port=1666 security_model=v3 security_name_v3=ACTrapUser security_level=privacy host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}} state=present
    register: data

#snmp-agent target-host trap address udp-domain 10.135.48.55 udp-port 65535 params securityname cipher %^%#1$6ILSu"!X=&2}*NKA/4Ep*(+S]'xJ_Wzc"5s@(-j~bvEXis.UCO$ZUjCB:%%^%#
  - name: "snmp-agent target-host trap address udp-domain"
    ce_snmp_target_host: address=10.135.48.55 notify_type=trap recv_port=65535 security_name=%^%#1$6ILSu"!X=&2}*NKA/4Ep*(+S]'xJ_Wzc"5s@(-j~bvEXis.UCO$ZUjCB:%%^%# host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}} state=present
    register: data

#snmp-agent mib-view included isoview iso
  - name: "snmp-agent mib-view included isoview iso "
    ce_config: lines='snmp-agent mib-view included isoview iso' match=none host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

#snmp-agent trap enable
  - name: "config snmp traps"
    ce_snmp_traps: feature_name=all host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}} state=present
    register: data

#interface Nve1
#source ip 1.1.1.1
#vni 111 head-end peer-list protocol bgp
#vni 112 head-end peer-list protocol bgp
#vni 5001 head-end peer-list protocol bgp
#vni 5002 head-end peer-list protocol bgp
#vni 6001 head-end peer-list protocol bgp
#vni 6036 head-end peer-list protocol bgp
  - name: "interface Nve1"
    ce_interface: interface="Nve1" host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "set source ip, source ip is valid"
    ce_vxlan_tunnel: nve_name=Nve1 source_ip=1.1.1.1 state="present" host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "set vni peer list protocol_type"
    ce_vxlan_tunnel: nve_name=Nve1 vni_id={{item.vni}} protocol_type=bgp state="present" host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    with_items:
      - { vni: '111'}
      - { vni: '112'}
      - { vni: '5001'}
      - { vni: '5002'}
      - { vni: '6001'}
      - { vni: '6036'}

#bgp 10
#router-id 1.1.1.1
#group spine external
#peer spine as-number 100
#peer 100.100.100.1 as-number 100
#peer 100.100.100.1 group spine
#peer 100.100.100.3 as-number 100
#peer 100.100.100.3 group spine
#peer 100.100.100.5 as-number 100
#peer 100.100.100.5 group spine
#peer 100.100.100.9 as-number 100
#peer 100.100.100.9 group spine
#peer 100.100.100.13 as-number 100
#peer 100.100.100.13 group spine
#peer 111.111.111.1 as-number 100
#peer 111.111.111.1 group spine
#peer 111.111.111.3 as-number 100
#peer 111.111.111.3 group spine
#peer 111.111.111.5 as-number 100
#peer 111.111.111.5 group spine
#peer 111.111.111.9 as-number 100
#peer 111.111.111.9 group spine
#peer 111.111.111.13 as-number 100
#peer 111.111.111.13 group spine
  - name: "bgp 10"
    ce_bgp: as_number=10 state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}} state=present
    register: data

  - name: "router-id ip"
    ce_bgp: router_id=1.1.1.1 state=present  host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "group "
    ce_config: parents='bgp 10' lines='group spine external, peer spine as-number 100' match=none host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "present bgp peer"
    ce_bgp_neighbor: peer_addr={{item.ip}} remote_as=100 state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    with_items:
      - { ip: '100.100.100.1'}
      - { ip: '100.100.100.3'}
      - { ip: '100.100.100.5'}
      - { ip: '100.100.100.9'}
      - { ip: '100.100.100.13'}
      - { ip: '111.111.111.1'}
      - { ip: '111.111.111.3'}
      - { ip: '111.111.111.5'}
      - { ip: '111.111.111.9'}
      - { ip: '111.111.111.13'}

  - name: "bgp peer group"
    ce_config: parents='bgp 10' lines=' peer 100.100.100.1 group spine, peer 100.100.100.3 group spine, peer 100.100.100.5 group spine, peer 100.100.100.7 group spine, peer 100.100.100.9 group spine, peer 100.100.100.13 group spine, peer 111.111.111.1 group spine, peer 111.111.111.3 group spine, peer 111.111.111.5 group spine, peer 111.111.111.7 group spine, peer 111.111.111.9 group spine, peer 111.111.111.13 group spine' match=none host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

#bgp 10
#ipv4-family unicast
#network 1.1.1.1 255.255.255.255
#network 1.1.1.2 255.255.255.255
#network 23.0.0.0 255.0.0.0 
#network 100.68.134.0 255.255.255.192
#network 32.32.32.0 255.255.255.0
#maximum load-balancing 8
#compare-different-as-med
  - name: "enable bgp network route"
    ce_bgp_af: af_type=ipv4uni network_address={{ item.ip }} mask_len={{ item.mask }} state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    with_items:
      - { ip: '1.1.1.1', mask: '32'}
      - { ip: '1.1.1.2', mask: '32'}
      - { ip: '23.0.0.0', mask: '8'}
      - { ip: '100.68.134.0', mask: '26'}
      - { ip: '32.32.32.0', mask: '24'}

  - name: "maximum load-balancing"
    ce_bgp_af: af_type=ipv4uni maximum_load_balance=8 state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "compare-different-as-med"
    ce_config: parents='bgp 10,ipv4-family unicast' lines='compare-different-as-med' host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

#bgp 200 instance overlay
  - name: "bgp 200 instance overlay"
    ce_evpn_bgp_rr: as_number=200 bgp_instance=overlay host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

#bridge-domain 4001
#bridge-domain 4002
#bridge-domain 4003
#bridge-domain 4004
#bridge-domain 4005
  - name: "bridge-domain 9910003"
    ce_vxlan_global: bridge_domain_id={{item.id}} state="present" host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    with_items:
      - { id: '4001'}
      - { id: '4002'}
      - { id: '4003'}
      - { id: '4004'}
      - { id: '4005'}

#interface 10GE1/0/1.1001 mode l2
#interface 10GE1/0/1.1002 mode l2
#interface 10GE1/0/1.1003 mode l2
#interface 10GE1/0/1.1004 mode l2
#interface 10GE1/0/1.1005 mode l2
  - name: "interface 10GE1/0/1.1021 mode l2"
    ce_interface: interface={{ item.interface }} l2sub=true host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    with_items:
      - { interface: '10GE1/0/1.1001'}
      - { interface: '10GE1/0/1.1002'}
      - { interface: '10GE1/0/1.1003'}
      - { interface: '10GE1/0/1.1004'}
      - { interface: '10GE1/0/1.1005'}


#interface 10GE1/0/1.1001 mode l2
#bridge-domain 4001
#interface 10GE1/0/1.1002 mode l2
#bridge-domain 4002
#interface 10GE1/0/1.1003 mode l2
#bridge-domain 4003
#interface 10GE1/0/1.1004 mode l2
#bridge-domain 4004
#interface 10GE1/0/1.1005 mode l2
#bridge-domain 4005
  - name: "l2_sub_interface "
    ce_vxlan_vap: bridge_domain_id={{ item.bd }} l2_sub_interface={{ item.interface }} state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    with_items:
      - { bd: '4001', interface: '10GE1/0/1.1001'}
      - { bd: '4002', interface: '10GE1/0/1.1002'}
      - { bd: '4003', interface: '10GE1/0/1.1003'}
      - { bd: '4004', interface: '10GE1/0/1.1004'}
      - { bd: '4005', interface: '10GE1/0/1.1005'}

#bridge-domain 9910003
#vxlan vni 9910003
#arp broadcast-suppress enable
#arp l2-proxy gateway-mac
#evpn
#route-distinguisher 0:9910003
#vpn-target  0:9910001 export-extcommunity
#vpn-target  0:9910003 export-extcommunity
#vpn-target  0:9910003 import-extcommunity
  - name: "bridge-domain 9910003"
    ce_vxlan_global: bridge_domain_id=9910003 state="present" host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "add vni_id and bridge_domain_id again"
    ce_vxlan_tunnel: vni_id=9910003 bridge_domain_id=9910003 state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "arp broadcast-suppress enable"
    ce_vxlan_arp: bridge_domain_id=9910003 arp_suppress=enable host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "arp l2-proxy gateway-mac"
    ce_config: lines='bridge-domain 9910003, arp l2-proxy gateway-mac' match=none host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "bridge-domain 10"
    ce_evpn_bd_vni: bridge_domain_id=9910003 evpn=true host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "config vpn target export-extcommunity & import-extcommunity"
    ce_evpn_bd_vni: bridge_domain_id=9910003 route_distinguisher=0:9910003 vpn_target_both=0:9910003 host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "config vpn target export-extcommunity & import-extcommunity"
    ce_evpn_bd_vni: bridge_domain_id=9910003  vpn_target_export=0:9910001 host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

  - name: "ip vpn-instance 4131"
    ce_vrf: vrf=4131 state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

#ip vpn-instance 110
#vxlan vni 600
  - name: "check vpn_vni 3"
    ce_vxlan_gateway: vpn_vni=600 vpn_instance=110 state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    
#interface Vbdif9910601
#ip binding vpn-instance 4131
#interface Vbdif9910602
#ip binding vpn-instance 4131
#interface Vbdif9910603
#ip binding vpn-instance 4131
#interface Vbdif9910604
#ip binding vpn-instance 4131
#interface Vbdif9910605
#ip binding vpn-instance 4131
  - name: "interface Vbdif"
    ce_interface: interface={{ item.interface }}  host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    with_items:
      - { interface: 'Vbdif9910601'}
      - { interface: 'Vbdif9910602'}
      - { interface: 'Vbdif9910603'}
      - { interface: 'Vbdif9910604'}
      - { interface: 'Vbdif9910605'}

  - name: "invalid interface"
    ce_vrf_interface: vpn_interface={{ item.interface }} vrf={{ item.vpn }} host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    with_items:
      - { interface: 'Vbdif9910601', vpn: '4131'}
      - { interface: 'Vbdif9910602', vpn: '4131'}
      - { interface: 'Vbdif9910603', vpn: '4131'}
      - { interface: 'Vbdif9910604', vpn: '4131'}
      - { interface: 'Vbdif9910605', vpn: '4131'}

#interface Vbdif9910601
#ip address 10.4.1.254 255.255.255.0 
#arp distribute-gateway enable 
#arp collect host enable
#interface Vbdif9910602
#ip address 10.4.2.254 255.255.255.0 
#arp distribute-gateway enable 
#arp collect host enable
#interface Vbdif9910603
#ip address 10.4.3.254 255.255.255.0 
#arp distribute-gateway enable 
#arp collect host enable
#interface Vbdif9910604
#ip address 10.4.4.254 255.255.255.0 
#arp distribute-gateway enable 
#arp collect host enable
#interface Vbdif9910605
#ip address 10.4.5.254 255.255.255.0 
#arp distribute-gateway enable 
#arp collect host enable
  - name: "set ipv4 address"
    ce_ip_interface: interface={{ item.interface }} version=v4 addr={{ item.ip }} mask={{ item.mask }} state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    with_items:
      - { interface: 'Vbdif9910601', ip: '10.4.1.254', mask: '24'}
      - { interface: 'Vbdif9910602', ip: '10.4.2.254', mask: '24'}
      - { interface: 'Vbdif9910603', ip: '10.4.3.254', mask: '24'}
      - { interface: 'Vbdif9910604', ip: '10.4.4.254', mask: '24'}
      - { interface: 'Vbdif9910605', ip: '10.4.5.254', mask: '24'}

  - name: "set vbdif arp distribute gateway enable"
    ce_vxlan_gateway: vbdif_name={{ item.interface }} arp_distribute_gateway=enable  state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    with_items:
      - { interface: 'Vbdif9910601'}
      - { interface: 'Vbdif9910602'}
      - { interface: 'Vbdif9910603'}
      - { interface: 'Vbdif9910604'}
      - { interface: 'Vbdif9910605'}

  - name: "set arp collect host enable"
    ce_vxlan_arp: vbdif_name={{ item.interface }} arp_collect_host=enable host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
    with_items:
      - { interface: 'Vbdif9910601'}
      - { interface: 'Vbdif9910602'}
      - { interface: 'Vbdif9910603'}
      - { interface: 'Vbdif9910604'}
      - { interface: 'Vbdif9910605'}

#evpn-overlay enable 
  - name: "evpn-overlay enable"
    ce_evpn_global: evpn_overlay_enable=true host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

#dldp enable
  - name: "dldp enable"
    ce_dldp: enable=true  host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

#sflow agent ip 192.108.70.49
  - name: "sflow agent ip"
    ce_sflow: agent_ip=192.108.70.49 state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data

#sflow collector 1 ip 192.109.110.50 udp-port 9995
  - name: "sflow collector"
    ce_sflow: collector_id=1 collector_ip=192.109.110.50 collector_udp_port=9995 state=present host={{inventory_hostname}} username={{username}} password={{password}} port={{ansible_ssh_port}}
    register: data
```