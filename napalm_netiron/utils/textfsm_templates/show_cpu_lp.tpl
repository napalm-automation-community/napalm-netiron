Value SLOT (\d+)
Value UTIL (\d+)

Start
  ^SLOT\s+ -> Continue
  ^\s+${SLOT}:\s+\d+\s+\d+\s+\d+\s+${UTIL} -> Next.Record

EOF