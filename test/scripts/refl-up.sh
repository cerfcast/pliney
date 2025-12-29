# Create a network configuration that is useful for testing the XDP runner.
# You _must_ source this file.
#
# As a result of using this configuration file, you will have a network namespace configuration like:
# |------------------------------|
# |               reflbr         |
# |              (a bridge)      |
# |          (192.168.129.1/24)  |
# |              |+++++++++++|   |
# |              |^^^        |   |
# |              |refleths0m |   |
# |  Local host    | |           |
# |------------------------------|
#                  |v|
#                  |e|
#                  |t|
#                  |h|
# |------------------------------|
# |                | |           |
# |               |^^^        |  |
# |               |refleths0  |  |
# |                              |
# |  Local host (namespace refl) |
# |------------------------------|


# Create the namespace
ip netns add refl
ip netns set refl 1

# Create the bridge (local host), with IP address.
ip link add reflbr type bridge
# TODO: Parameterize this configuration.
ip addr add 192.168.129.1/24 dev reflbr
# Up the bridge.
ip link set reflbr up

# Now, create the veth with the refl namespace.
ip link add refleths0 type veth peer name refleths0m

# Put refleths0 into the refl name space.
ip link set refleths0 netns refl
# Up it!
ip netns exec refl ip link set refleths0 up

# Finally, put the veth (outside namespace) into the bridge.
ip link set refleths0m up
ip link set refleths0m master reflbr
