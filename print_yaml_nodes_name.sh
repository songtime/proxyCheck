cat yaml_nodes.txt | awk -F, '{print $1}' | awk -F': ' -v OFS="," '{printf $2","}'
