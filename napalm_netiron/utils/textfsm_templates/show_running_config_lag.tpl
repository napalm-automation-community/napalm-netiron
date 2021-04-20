Value Name (.*)
Value Type (\S+)
Value Id (\d+)
Value Ports (.*)

Start
  ^lag "${Name}" ${Type} id ${Id}
  ^\s+ports ${Ports}
  ^! -> Record