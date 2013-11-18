local Guard = require("guard")
local Conf = require ("config")
Guard.config.filename = ngx.var.request_filename
Guard.config.logDebug = Dict:get("logDebug")
Guard.config.extensionProtectReg = Dict:get("extensionProtectReg")
--只对指定的扩展文件作保护
if Guard:isFileExtensionProtect() then
	--载入变量
	Guard:loadConfig()	
	--定义变量
	Guard.config.reqMethod = ngx.var.request_method
	Guard.config.reqHeader = ngx.req.get_headers()
	Guard.config.ref = ( Guard.config.reqHeader["Referer"] or "-" )
	Guard.config.userAgent = ( Guard.config.reqHeader["User-Agent"] or "-" )
	Guard.config.ip = ngx.var.remote_addr
	Guard.config.realClientIP = Guard:getRealClientIP()
	Guard.config.userIdentify = Guard:getUserIdentify()
	Guard.config.uri = ngx.var.request_uri
	Guard.config.unescape_uri = ngx.unescape_uri(Guard.config.uri)
	Guard.config.host = ngx.var.host
	Guard.config.url = table.concat({Guard.config.host,Guard.config.unescape_uri})
	--判断ip是否在文件ip白名单,文件ip黑名单,字典ip黑名单
	if Guard:inWhiteIPList() then
		return 
	elseif Guard:inBlackIPList() then
		Guard:returnError()
	elseif Guard:inBlackDic() then
		Guard:returnError()
	end
	
	--GET请求过滤
	if Guard.config.reqMethod == "GET" then
 		Guard:getFilter()
 	end	

 	--POST请求过滤
 	if Guard.config.reqMethod == "POST" then
		Guard:postWhite()
 		Guard:postFilter()
 	end

 	--cookie过滤
 	Guard:cookieFilter()
 
  	--user_agent过滤
 	Guard:useragentFilter()

 	--cc攻击过滤
 	Guard:ccFilter()
end	


