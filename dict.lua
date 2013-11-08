local function getRealClientIP(ip)
	if realIPViaHeader then
		if reqHeader[realIPViaHeader] then
			return reqHeader[realIPViaHeader]
		else
			return ip
		end	
		
	else
		return ip
	end	
end
local ip = ngx.var.remote_addr
local reqHeader = ngx.req.get_headers()
local realIPViaHeader = Dict:get("realIPViaHeader")
local realClientIP = getRealClientIP(ip)
local setDictAllowIP = Dict:get("setDictAllowIP")
local args = ngx.req.get_uri_args()
local action = args["action"]
local key = args["key"]
local value = args["value"]
local exp = ( args["exp"] or 0 )
local flag = args["flag"]
if ngx.re.match(realClientIP,setDictAllowIP,"isjo") then
	if action and action == "get" then
		if key then
			local value = Dict:get(key)
			if value then
				ngx.print(key," = ",value)
				ngx.exit(200)
			else
				ngx.print(key," not found.")
				ngx.exit(200)
			end
		else
			ngx.print("need args key.")
		end
	elseif action and action == "set" then
		if key and value then
			if flag then
				 local succ, err, forcible = Dict:set(key, value, exp, flag)
				 if succ then
					ngx.print("succ set key="..key.." value="..value.." exp="..exp.." flag"..flag)
					ngx.exit(200)
				 else
					ngx.print(err)
					ngx.exit(200)
				 end
			else
				 local succ, err, forcible = Dict:set(key, value, exp)
				 if succ then
					ngx.print("succ set key="..key.." value="..value.." exp="..exp)
					ngx.exit(200)
				 else
					ngx.print(err)
					ngx.exit(200)
				 end
			end
		else
			ngx.print("key and value both need.")
			ngx.exit(200)
		end
	else
		ngx.print("action not found or action invalid.")
	end
else
	ngx.print("your ip address is not allow.")	
end
