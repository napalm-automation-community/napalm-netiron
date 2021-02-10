Value Required Port (\S+)
Value Link (up|down|disabled|empty)
Value PortState (\S+)
Value Speed (\S+)
Value Tag (tagged|untagged|dual)
Value Name (.*)
Value MTU (\d+)
Value Mac ([\da-f:\.]*)

Start
  ^${Port} is ${Link}
  ^\s+Configured.*speed.*actual ${Speed},
  ^\s+Hardware.*address is .*(bia ${Mac})
  ^.*port is in ${Tag} mode, port state is ${PortState}
  ^\s+Port name is ${Name}
  ^.*(IPv6 ){0}MTU ${MTU} -> Record
