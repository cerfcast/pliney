local pliney = _G.PLINEY_SOCKET
print(pliney)
local socket = require("socket")
print(pliney:send("TESTING")