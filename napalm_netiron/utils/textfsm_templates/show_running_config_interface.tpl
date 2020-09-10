Value Filldown Interface (\S+)
Value Filldown InterfaceNum (\S+)
Value Ipv4address (\S+)
Value Ipv6address (\S+)

Start
  ^interface ${Interface} ${InterfaceNum}
  ^\s+ip address ${Ipv4address} -> Record
  ^\s+ipv6 address ${Ipv6address} -> Record
  ^! -> Clearall
