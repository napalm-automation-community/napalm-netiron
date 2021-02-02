Value Vlan (\d+)
Value Name (\S+)
Value Ve (\S+)
Value TaggedPorts (.*)
Value UntaggedPorts (.*)

Start
  ^PORT-VLAN ${Vlan}, Name ${Name},
  ^Statically tagged Ports\s+: ${TaggedPorts}
  ^Untagged Ports\s+: ${UntaggedPorts}
  ^Associated Virtual Interface Id: ${Ve} -> Record
