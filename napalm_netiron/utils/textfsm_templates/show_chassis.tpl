Value NAME (.*)
Value STATUS (.*)
Value SPEED (\S+)
Value VALUE (\S+)
Value VALUE2 (.*)
Value TEMP ([0-9]*\.[0-9]*\S+)
Value TEMP2 ([0-9]*\.[0-9]*\S+)
Value Filldown RKEY (POWER|FAN|TEMP)

Start
  ^---\s*${RKEY}S --- -> Continue
  ^--- ${RKEY} -> Continue
  ^Power\s+${NAME}:\s+.*AC\s+${VALUE}\):\s+Installed\s+\(${STATUS}\) -> Next.Record
  ^Power\s+${NAME}:\s+${STATUS} -> Next.Record
  ^Total\s+Power\s.*${NAME}\s+=\s+.${VALUE} -> Next.Record
  ^${NAME}\s+.*type=${VALUE2}=${VALUE} -> Next.Record
  ^--- ${RKEY}S -> Fans

Fans
  ^${NAME}:\s+Status = ${STATUS},\s+Speed = ${SPEED}\s+ -> Next.Record
  ^--- ${RKEY}ERA -> Temp

Temp
  ^${NAME}\s+Module:\s+${TEMP}\s+${TEMP2} -> Next.Record
  ^${NAME}\s:{VALUE2}:${TEMP} -> Next.Record
  ^${NAME}:\s+${TEMP} -> Next.Record
  ^--- -> End

End