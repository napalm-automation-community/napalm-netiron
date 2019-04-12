Value uptime (.*)
Value update_source (.*)
Value next_hop_self (\S+)
Value address_family (\S+)
Value send_community (\S+)
Value send_extended_community (\S+)
Value route_map (.*)
Value prefix_list (.*)
Value filter_list (.*)
Value description (.*)
Value peer_group (\S+)
Value routing_table (\S+)
Value connection_state (\S+)
Value previous_connection_state (\S+)
Value multihop (\d+)
Value remove_private_as (\S+)
Value remote_as (\d+)
Value local_as (\d+)
Value router_id (\S+)
Value local_address (\S+)
Value local_port (\d+)
Value remote_address (\S+)
Value remote_port (\d+)
Value holdtime (\d+)
Value keepalive (\d+)

Start
  ^\d+\s+IP Address: ${remote_address}, AS: ${remote_as} \((IBGP|EBGP)\), RouterID: ${router_id}, VRF: ${routing_table}
  ^\s+Description: ${description}
  ^\s+State: ${connection_state}, Time: ${uptime}, KeepAliveTime: ${keepalive}, HoldTime: ${holdtime}
  ^\s+PeerGroup: ${peer_group}
  ^\s+UpdateSource: ${update_source}
  ^\s+NextHopSelf: ${next_hop_self}
  ^\s+RemovePrivateAs:\s+:\s+${remove_private_as}
  ^\s+Address Family\s*: ${address_family} .*
  ^\s+SendCommunity: ${send_community}
  ^\s+SendExtendedCommunity: ${send_extended_community}
  ^\s+Route-map: ${route_map}
  ^\s+Prefix-list: ${prefix_list}
  ^\s+Filter-list: ${filter_list}
  ^\s+Last Connection Reset Reason:${previous_connection_state}
  ^\s+Multihop-EBGP: ${multihop}
  ^\s+Local host:\s+${local_address}, Local\s+Port: ${local_port}
  ^.*, Remote Port: ${remote_port}
  ^\s+SendQue: .* -> Next.Record
  ^Error: .* -> Next.Record

