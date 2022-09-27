Value Interface (\S+?)
Value Admin (Up|Down)
Value Oper (Up|Down)
Value LDP (YES|NO)

Start
  ^\s+${Interface}(\(\S+\))?\s+.*${Admin}\s+${Oper}.*${LDP} -> Record