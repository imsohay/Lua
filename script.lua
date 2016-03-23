#!/usr/bin/lua


-- simple tiny port scanner
-- program try to find open TCP ports of host among first 1000
-- if program runs for a long time(without progress), so there is firewall



local socket = require("socket")
local tcp = assert(socket:tcp())

function check_target(target)
	if string.match(target, "(%d+)%.(%d+)%.(%d+)%.(%d+)") == nil then 
		local result = socket.dns.toip(target)
		if result == nil then 
			print('failed to resolve hostname')
			os.exit()
		end

		return result
	end

	for num in string.gmatch(target, "%d+") do
		num = tonumber(num)
		if num < 0 or num > 255 then 
			print('not correct target address')
			os.exit()
		end
	end

	return target
end


function parse_arguments()
	local host

	if not (#arg == 1) then 
		print('usage: script [<host_ip_address>|<sitename>]')
		os.exit()
	else	
		host = arg[1]
	end

	return check_target(host)
end



function do_scan(host)
	print('scan started...')
	local out = ''
	for i = 1,1000,1 do
		if i % 100 == 0 then 
			print('		'..tostring(i / 10)..'% completed')
		end
		local res, s = socket:tcp():connect(host, i)
		
		local s = tostring(i)
		if not (res == nil) then
			out = out..'		port '..s..' open\n'
		end
		tcp:close()
	end

	print('scan finished\n\nresults for '..host..':\n')

	if out == '' then
		out = '		All 1000 scanned ports are closed or filtered\n'
	end
	return out
end


local host = parse_arguments()
print(do_scan(host))


