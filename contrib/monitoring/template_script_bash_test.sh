#!/bin/bash

# In this exemple the event variable is remplaced by the JSON string
var=$(cat <<EOF
@@@@@event@@@@@
EOF
)
echo "___________print in bash the json string"
echo $var
echo "__________________________________________________________"
echo "print json information"
echo $var | jq '.mon_machine_hostname'
echo "______________________ END PROGRAMME _____________________"
