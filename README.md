This a tool to from a main node copy the root SSH public keys to multiple nodes only using standard python libraries. 

Also to check that passwordless SSH is working from a main node against those nodes listed as target.

The list of nodes can be passed as parameter on run or in an input file.

**TODO:**
 * Able to run for non-root (?)
 

**PREREQUISITES:** Before running this tool you **must** fulfill the prerequisites:
 * python version 3 installed in the system
 * ssh, ssh-copy-id, and sshpass commands avaiable on main node


**PARAMETERS:**
The tool requires one, and only one, of the two following parameters to be passed on during invocation:
 * --hosts -> Comma separated value (CSV) string of nodes to copy the keys to. Nodes can be IPv4, IPv6 or hostnames
 * -f or --hosts-file -> File name containing in CSV format the nodes to copy the keys to. Nodes can be IPv4, IPv6 or hostnames


The following optional parameters can be also be passed:
 * -c or --check -> Do not copy any SSH key, just check that passwordless from main node works to the nodes passed
 * -d or --debug -> Print verbose information on screen and not only on the debug file
 * -v or --version -> Print the version of the tool and exit

