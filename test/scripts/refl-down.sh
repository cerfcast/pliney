# Undo the created configuration in refl-up.sh
# See that script for additional documentation.

ip netns del refl
ip link del dev reflbr
ip link del dev refleths0m 

