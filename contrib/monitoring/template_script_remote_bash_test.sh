#!/bin/bash

# In this exemple the event variable is remplaced by the JSON string
# ----- start program on remote machine ----
var=$(cat <<EOF
@@@@@event@@@@@
EOF
)

# bach exec on remote machine
echo "___________print in bash the json string"
echo $var

echo "print json information"
echo $var | jq '.mon_machine_hostname'
systemctl list-units --type=service
# ______________________ END PROGRAMME _____________________"
