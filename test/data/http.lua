local pliney = _G.PLINEY_SOCKET
print(pliney)
local socket = require("socket")

-- Send an HTTP response to cnn.com
print(pliney:send("HTTP / HTTP/1.1\nHost: www.cnn.com\n\n"))
response = pliney:receive()
print(string.format("Response: %s", response))