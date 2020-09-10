Value Port (\S+)
Value Link (Up|Down|Disabled)
Value PortState (\S+)
Value Speed (\S+)
Value Tag (Yes|No|N/A)
Value Mac (\S+)
Value Name (.*)

Start
  ^${Port}\s+${Link}\s+${PortState}\s+${Speed}\s+${Tag}\s+${Mac}\s+${Name} -> Record