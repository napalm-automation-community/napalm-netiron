Value Filldown NAME (\S+)
Value Filldown STATE (\S+)
Value Filldown MODULE (\S+)
Value AVAIL_RAM (\d+)
Value TOTAL_RAM (\d+)
Value AVAIL_RAM_PCT (\d+)

Start
  ^.*\s+${STATE}\s+${MODULE}\s+slot\s+${NAME}: -> Continue
  ^.*\s+${MODULE}\s+SL\s+${NAME}: -> Continue
  ^Total\s+SDRAM\s+:\s+${TOTAL_RAM}\s+bytes -> Continue
  ^Available\s+Memory\s+:\s+${AVAIL_RAM}\s+bytes -> Continue
  ^Available\s+Memory\s+\(%\):\s+${AVAIL_RAM_PCT}\s+percent -> Next.Record

EOF