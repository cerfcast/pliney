local pliney = _G.PLINEY_SOCKET

for i=0,9 do
	data = string.format("THIS IS SOME TESTING BYTES: %d", i)
	print(string.format("Send result: %d", pliney:send(data)))
end