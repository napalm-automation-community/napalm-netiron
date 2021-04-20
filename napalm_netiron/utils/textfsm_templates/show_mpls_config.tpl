Value Required Name (\S+)
Value Required Vcid (\d+)
Value Vlan (\d+)
Value Interface (\S+)

Start
  ^\s+vll ${Name} ${Vcid}
  ^\s+vlan ${Vlan}
  ^\s+tagged e(the)? ${Interface} -> Record
