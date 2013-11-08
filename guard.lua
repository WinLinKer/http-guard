local bit = require "bit"
local ffi = require "ffi"
local C = ffi.C
local bor = bit.bor
ffi.cdef[[
int write(int fd, const char *buf, int nbyte);
int open(const char *path, int access, int mode);
int close(int fd);
]]

local O_RDWR   = 0X0002; 
local O_CREAT  = 0x0040;
local O_APPEND = 0x0400;
local S_IRUSR = 0x0100;
local S_IWUSR = 0x0080;

local Guard = {config={}}

--从字典取出初始化阶段产生的变量
Guard.config.whiteIPList = Dict:get("whiteIPList")
Guard.config.blackIPList = Dict:get("blackIPList")
Guard.config.whiteIPList = Dict:get("whiteIPList")
Guard.config.errorHtmlStr = Dict:get("errorHtmlStr")
Guard.config.extensionProtectReg = Dict:get("extensionProtectReg")
Guard.config.cookieKey = Dict:get("cookieKey")
Guard.config.getRule = Dict:get("getRule")
Guard.config.postRule = Dict:get("postRule")
Guard.config.cookieRule = Dict:get("cookieRule")
Guard.config.jsJumpRule = Dict:get("jsJumpRule")
Guard.config.postWhiteRule = Dict:get("postWhiteRule")

--从字典取出config.lua的变量
Guard.config.autoDeny = Dict:get("autoDeny")
Guard.config.dictName = Dict:get("dictName")
Guard.config.dictExpiresTime = Dict:get("dictExpiresTime")
Guard.config.attackTimes = Dict:get("attackTimes")
Guard.config.denySeconds = Dict:get("denySeconds")
Guard.config.fileExtensionProtect = Dict:get("fileExtensionProtect")
Guard.config.errorReturn = Dict:get("errorReturn")
Guard.config.realIPViaHeader = Dict:get("realIPViaHeader")
Guard.config.clientIdentify = Dict:get("clientIdentify")
Guard.config.ipWhiteModule = Dict:get("ipWhiteModule")
Guard.config.ipWhiteListPath = Dict:get("ipWhiteListPath")
Guard.config.ipBlackModule = Dict:get("ipBlackModule")
Guard.config.ipBlackListPath = Dict:get("ipBlackListPath")
Guard.config.logModule = Dict:get("logModule")
Guard.config.logDebug = Dict:get("logDebug")
Guard.config.logSavePath = Dict:get("logSavePath")
Guard.config.getFilterModule = Dict:get("getFilterModule")
Guard.config.getUrlPatternPath = Dict:get("getUrlPatternPath")
Guard.config.postWhiteModule = Dict:get("postWhiteModule")
Guard.config.postWhiteUrlPath = Dict:get("postWhiteUrlPath")
Guard.config.postFilterModule = Dict:get("postFilterModule")
Guard.config.uploadExtensionDeny = Dict:get("uploadExtensionDeny")
Guard.config.fileExtension = Dict:get("fileExtension")
Guard.config.postPatternPath = Dict:get("postPatternPath")
Guard.config.cookieFilterModule = Dict:get("cookieFilterModule")
Guard.config.cookiePatternPath = Dict:get("cookiePatternPath")
Guard.config.ccAttackFilterModule = Dict:get("ccAttackFilterModule")
Guard.config.urlVisitTimes = Dict:get("urlVisitTimes")
Guard.config.CCBlackDicExpiresTime = Dict:get("CCBlackDicExpiresTime")
Guard.config.jsJumpCodeSend = Dict:get("jsJumpCodeSend")
Guard.config.jsVerifyWhiteTime = Dict:get("jsVerifyWhiteTime")
Guard.config.jsJumpProtectUrlPath = Dict:get("jsJumpProtectUrlPath")
Guard.config.clientIPDebug = Dict:get("clientIPDebug")
Guard.config.guardMode = Dict:get("guardMode")
Guard.config.randomKey = Dict:get("randomKey")
Guard.config.setDictAllowIP = Dict:get("setDictAllowIP")


--debug日志输出
function Guard:debug(data)
	if string.lower(self.config.logDebug) == "on" then
		self.config.currentModule = (self.config.currentModule or "unkown module")
		data = "["..self.config.currentModule.."]"..data
		if self.config.clientIPDebug then
			if self.config.realClientIP == self.config.clientIPDebug then
				ngx.log(ngx.ERR,data)
			end	
		else	
			ngx.log(ngx.ERR,data)
		end	
	end	
end	

--日志写入
function Guard:writeLog(data)
	self:debug("write log "..data.." to log file "..self.config.logSavePath)
	local logger_fd = C.open(self.config.logSavePath, bor(O_RDWR, O_CREAT, O_APPEND), bor(S_IRUSR,S_IWUSR));
	local c = data;
	C.write(logger_fd, c, #c);
	C.close(logger_fd)
end

--获取客户端真实ip
function Guard:getRealClientIP()
	if self.config.realIPViaHeader then
		if self.config.reqHeader[self.config.realIPViaHeader] then
			self:debug("realIPViaHeader is set.return "..self.config.reqHeader[self.config.realIPViaHeader])
			return self.config.reqHeader[self.config.realIPViaHeader]
		else
			self:debug("reqHeader[realIPViaHeader] not found return ip "..self.config.ip)
			return self.config.ip
		end	
		
	else
		self:debug("realIPViaHeader not set.return ip. "..self.config.ip)
		return self.config.ip
	end	
end

--设置当前模块名,用于debug显示
function Guard:setCurrentModule(module)
	if string.lower(self.config.logDebug) == "on" then
		self.config.currentModule = module
	end
end

--获取表数量
function Guard:tlen(t)
   local c = 0
   for k,v in pairs(t) do
        c = c+1
   end
   return c
end

--获取字典
function Guard:dictGet(key)
	local value, flags = Dict:get(key)
	if value then
		self:debug(" get a value "..value.." from key "..key)
	else
		self:debug(" get none value from key "..key)
	end
	return value, flags
end

--设置字典
function Guard:dictSet(key, value, exptime,...)
	local arg = {...}
	if table.getn(arg) == 1 then
		local flags = arg[1]
		local succ, err, _ = Dict:set(key, value, exptime,flags)
		if not succ then
			ngx.log(ngx.ERR,err)
			return false
		else
			self:debug(" set a dict,key "..key.."  value "..value.." exptime "..exptime)
			return true
		end		
	elseif table.getn(arg) == 0 then
		local succ, err, _ = Dict:set(key, value, exptime)
	        if not succ then
			ngx.log(ngx.ERR,err)
			return false
		else
			self:debug(" set a dict,key "..key.."  value "..value.." exptime "..exptime)
			return true
		end
	end
end

--字典值递增
function Guard:dictIncr(key, value)
	local newval, err = Dict:incr(key, 1)
	if err then
		ngx.log(ngx.ERR,err)
	else
		self:debug(" incr a key "..key.." value "..value)
	end
	return newval, err
end

--判断ip是否在白名单
function Guard:inWhiteIPList()
	self:setCurrentModule("inWhiteIPList")
	if string.lower(self.config.ipWhiteModule) == "on" then
		self:debug(" modules is enable.")
		if ngx.re.match(self.config.realClientIP,self.config.whiteIPList) then
			self:debug(" client "..self.config.realClientIP.." match rule "..self.config.whiteIPList)
			return true
		else
			return false
		end
	else
		self:debug(" modules is disabled.")
	end	
end

--判断ip是否在黑名单列表
function Guard:inBlackIPList()
	self:setCurrentModule("inBlackIPList")
	if string.lower(self.config.ipBlackModule) == "on" then
		self:debug(" modules is enable.")
		if ngx.re.match(self.config.realClientIP,self.config.blackIPList) then
			self:debug(" client "..self.config.realClientIP.." match rule "..self.config.blackIPList)
			return true
		else
			self:debug(" client "..self.config.realClientIP.." not match rule "..self.config.blackIPList)
			return false
		end
	else
		self:debug(" modules is disabled.")
	end	
end

--判断ip是否在黑名单字典
function Guard:inBlackDic()
	if self:dictGet(self.config.realClientIP,"isBlackDic") then
		self:setCurrentModule("inBlackDic")
		self:debug(" client "..self.config.realClientIP.." in black dict.")
		self:returnError()
	end
end

--判断请求的文件名是否需要保护
function Guard:isFileExtensionProtect()
	self:setCurrentModule("isFileExtensionProtect")
	if ngx.re.match(self.config.filename,self.config.extensionProtectReg,"i") then
		self:debug(" filename "..self.config.filename.." match rule "..self.config.extensionProtectReg)
		return true
	else
		self:debug(" filename "..self.config.filename.." not match rule "..self.config.extensionProtectReg)
		return false
	end
end	

--自动防攻击
function Guard:autoDeny()
	if string.lower(self.config.autoDeny) == "on" then
		self:setCurrentModule("autoDeny")
		self:debug(" is enable.")
		local filterIdentify = table.concat({self.config.userIdentify,"filter"})
		local v, _ = self:dictGet(filterIdentify,autoDeny)
		if v then
			if v > self.config.attackTimes then
				self:debug(" client "..self.config.realClientIP.."attack "..self.config.attackTimes.." exceed "..v.." times.deny "..self.config.denySeconds.." seconds")
				self:dictSet(self.config.realClientIP,1,self.config.denySeconds)
				self:returnError()
			else
				self:dictIncr(filterIdentify,1,"autoDeny")
			end
		else
			self:dictSet(filterIdentify, 1, self.config.dictExpiresTime)
		end
	end
end

--GET过滤
function Guard:getFilter()
	if string.lower(self.config.getFilterModule) == "on" then
		self:setCurrentModule("getFilter")
		self:debug(" modules is enable.")
		if ngx.re.match(self.config.url,self.config.getRule,"isjo") then
			self:debug("  client "..self.config.realClientIP.." url"..self.config.url.." match rule "..self.config.getRule)
			local data = table.concat({ngx.localtime(),"getFilterModule",self.config.realClientIP,self.config.url,self.config.ref,self.config.userAgent.."\n"},"|")
			self:writeLog(data)
			self:autoDeny()
			self:returnError()
		else
			self:debug("  client "..self.config.realClientIP.." url"..self.config.url.." not match rule "..self.config.getRule)
		end	
	end	
end

--POST白名单
function Guard:postWhite()
	if string.lower(self.config.postWhiteModule) == "on" then
		self:setCurrentModule("postWhite")
		self:debug(" modules is enable.")
		if not (ngx.re.match(self.config.url,self.config.postWhiteRule,"isjo")) then
			self:debug(" url "..self.config.url.." not match rule "..self.config.postWhiteRule)
			local data = table.concat({ngx.localtime(),"postWhiteModule",self.config.realClientIP,self.config.url,self.config.ref,self.config.userAgent.."\n"},"|")
			self:writeLog(data)
			self:returnError()
		end
	end
end

--POST内容过滤
function Guard:postFilter()
	if string.lower(self.config.postFilterModule) == "on" or string.lower(self.config.uploadExtensionDeny) == "on" then
		self:setCurrentModule("postFilter")
		local contentType = self.config.reqHeader["Content-Type"]
		ngx.req.read_body()
		local body = ( ngx.req.get_body_data() or "")
		if contentType then
			if ngx.re.match(contentType,"multipart/form-data; boundary") then
				self:debug(" contentType "..contentType.." match multipart/form-data; boundary")
				if string.lower(self.config.uploadExtensionDeny) == "on" then
					self:setCurrentModule("postFilter:uploadExtensionDeny")
					self:debug(" is enable.")
					if ngx.re.match(body,"Content-Disposition: form-data;.*filename=\".*\\."..self.config.fileExtension.."\"","isjo") then
						self:debug(" body match "..self.config.fileExtension)
						local data = table.concat({ngx.localtime(),"postUploadFilterModule",self.config.realClientIP,self.config.url,self.config.ref,self.config.userAgent.."\n"},"|")
						self:writeLog(data)
						self:autoDeny()
						self:returnError()	
					end
				end
			elseif ngx.re.match(contentType,"application/x-www-form-urlencoded") then
				self:setCurrentModule("postFilter:content")
				self:debug(" contentType "..contentType.." match application/x-www-form-urlencoded")
				if string.lower(self.config.postFilterModule) == "on" then
					self:debug(" modules is enable.")
					if ngx.re.match(body,self.config.postRule,"isjo") then
						self:debug(" body match rule "..self.config.postRule)
						local data = table.concat({ngx.localtime(),"postContentFilterModule",self.config.realClientIP,self.config.url,self.config.ref,self.config.userAgent,body.."\n"},"|")
						self:writeLog(data)
						self:autoDeny()
						self:returnError()
					end
				end
			
			end
		end	
	end
end

--Cookie过滤
function Guard:cookieFilter()
	if string.lower(self.config.cookieFilterModule) == "on" then
		self:setCurrentModule("cookieFilter")
		self:debug(" modules is enable.")
		local cookie = ngx.var.http_cookie
		if cookie then
			local requestCookie = ngx.unescape_uri(cookie)
			if ngx.re.match(requestCookie,self.config.cookieRule,"isjo") then 
				self:debug(" cookie "..requestCookie.."match rule "..self.config.cookieRule)
				local data = table.concat({ngx.localtime(),"cookieFilterModule",self.config.realClientIP,self.config.url,self.config.ref,self.config.userAgent,requestCookie.."\n"},"|")
				self:writeLog(data)
				self:autoDeny()
				self:returnError()
			end
		end
	end
end

--CC过滤
function Guard:ccFilter()
	if string.lower(self.config.ccAttackFilterModule) == "on" then
		self:setCurrentModule("ccFilter")
		self:debug(" modules is enable.")
		local ccIdentify = table.concat({self.config.userIdentify,"cc"})
		local ccTimes = self:dictGet(ccIdentify,"ccFilter")
		if ccTimes then
			local newCCTimes = self:dictIncr(ccIdentify, 1,"ccFilter")
			if newCCTimes > self.config.urlVisitTimes then
				self:debug(" client "..self.config.realClientIP.." visit times "..newCCTimes.." exceed "..self.config.urlVisitTimes)
				self:dictSet(self.config.realClientIP, 1, self.config.CCBlackDicExpiresTime)
				local data = table.concat({ngx.localtime(),"ccFilterModule",self.config.realClientIP,self.config.url,self.config.ref,self.config.userAgent.."\n"},"|")
				self:writeLog(data)
				self:returnError()
			end
		else
			self:debug(" dict not found.set key "..ccIdentify)
			self:dictSet(ccIdentify, 1, 60)
		end
	end

	if string.lower(self.config.jsJumpCodeSend) == "on" then
		self:setCurrentModule("ccFilter:jsJumpCodeSend")
		self:debug(" modules is enable.")
		if ngx.re.match(self.config.url, self.config.jsJumpRule, "isjo") then
			self:debug(" url match rule "..self.config.jsJumpRule)
			local jsCCIdentify = table.concat({self.config.realClientIP,"jscc"})
			local jsvalid, _ = self:dictGet(jsCCIdentify,"ccFilter:jsJumpCodeSend")
			local args = ngx.req.get_uri_args()
			if not jsvalid then
				self:debug(" not in white list")
				local urlccKeyValue = args["cckey"]
				if urlccKeyValue and type(urlccKeyValue) == "table" then
					urlccKeyValue=urlccKeyValue[table.getn(urlccKeyValue)]
				end	
				if urlccKeyValue and self:verifyKey(urlccKeyValue) then
					self:debug(" urlccKeyValue "..urlccKeyValue.." is valid ")
					self:dictSet(jsCCIdentify, 1, self.config.jsVerifyWhiteTime)
				else
					self:debug(" urlccKeyValue invalid ")
					jsRandomValue = self:makeRandomValue()
					if self:tlen(args) == 0 then
						newUrl = table.concat({self.config.uri,"?cckey=",jsRandomValue})
					else
						newUrl = table.concat({self.config.uri,"&cckey=",jsRandomValue})
					end	

					local jsJumpCode=table.concat({"<script>window.location.href='",newUrl,"';</script>"})
					self:debug(" send jscode "..jsJumpCode)
					ngx.header.content_type = "text/html"
					ngx.print(jsJumpCode)
					ngx.exit(200)
				end	
			end	
		end	
	end
end

--根据客户端ip以及启动时设置的随机数生成随机值
function Guard:makeRandomValue()
	local randomKey = self.config.randomKey
	math.randomseed( os.time() )
	local keyBefore = string.sub(ngx.md5(self.config.realClientIP),1,20)
	local keyAfter = math.random(100000,999999)
	--把0转为1
	local keyAfter = ngx.re.gsub(keyAfter,'0','1')
	local keyAfter1 = string.sub(keyAfter,1,1)
	local keyAfter2 = string.sub(keyAfter,2,2)
	local keyAfter3 = string.sub(keyAfter,3,3)
	local keyAfter4 = string.sub(keyAfter,4,4)
	local keyAfter5 = string.sub(keyAfter,5,5)
	local keyAfter6 = string.sub(keyAfter,6,6)
	local keyMid = table.concat({
				    string.sub(randomKey,keyAfter1,keyAfter1),
                    string.sub(randomKey,keyAfter2,keyAfter2),
                    string.sub(randomKey,keyAfter3,keyAfter3),
                    string.sub(randomKey,keyAfter4,keyAfter4),
                    string.sub(randomKey,keyAfter5,keyAfter5),
                    string.sub(randomKey,keyAfter6,keyAfter6)
                   })
	self:debug("make random value "..table.concat({keyBefore,keyMid,keyAfter}))				   	
	return table.concat({keyBefore,keyMid,keyAfter})

end

--验证cookie是否合法
function Guard:verifyKey(value)
	local randomKey = self.config.randomKey
	local keyBefore = string.sub(value,1,20)
	local keyMid = string.sub(value,21,26)
	local keyAfter = string.sub(value,27,32)
    local keyAfter1 = string.sub(keyAfter,1,1)
    local keyAfter2 = string.sub(keyAfter,2,2)
    local keyAfter3 = string.sub(keyAfter,3,3)
    local keyAfter4 = string.sub(keyAfter,4,4)
    local keyAfter5 = string.sub(keyAfter,5,5)
    local keyAfter6 = string.sub(keyAfter,6,6)
    local keyMidConcat = table.concat({
       					string.sub(randomKey,keyAfter1,keyAfter1),
                        string.sub(randomKey,keyAfter2,keyAfter2),
                        string.sub(randomKey,keyAfter3,keyAfter3),
                        string.sub(randomKey,keyAfter4,keyAfter4),
                        string.sub(randomKey,keyAfter5,keyAfter5),
                        string.sub(randomKey,keyAfter6,keyAfter6)
                       })
	local keyBeforeConcat = string.sub(ngx.md5(self.config.realClientIP),1,20)
	if keyBefore == keyBeforeConcat and keyMid == keyMidConcat then
		return true
	else
		return false
	end
	
end

--获取用户识别码
function Guard:getUserIdentify()
	if self.config.clientIdentify == "cookie" then	
		self:debug("clientIdentify is cookie.")
		--获取cookie的值
		self.config.cookieValue = ngx.var["cookie_guard"]
		if not self.config.cookieValue then
			local randomCookie = self:makeRandomValue()
			ngx.header['Set-Cookie'] = table.concat({"guard=",randomCookie,"; path=/"})
			self:debug("cookie not found.send cookie "..randomCookie.." and return realClientIP "..self.config.realClientIP)
			return self.config.realClientIP
		else
			self:debug("cookie found. verifyCookie "..self.config.cookieValue)
			if self:verifyKey(self.config.cookieValue) then
				self:debug(" cookie "..self.config.cookieValue.." is valid.return it.")
				return self.config.cookieValue
			else	
				self:debug(" cookie "..self.config.cookieValue.." is invalid.return realip "..self.config.realClientIP)
				local randomCookie = self:makeRandomValue()
				ngx.header['Set-Cookie'] = table.concat({"guard=",randomCookie,"; path=/"})
				self:debug("value invalid,send cookie and return realClientIP "..self.config.realClientIP)				
				return self.config.realClientIP
			end	
		end
	else
		self:debug("clientIdentify is ip.")
		return self.config.realClientIP
	end	
end

--返回错误
function Guard:returnError()
	if  string.match(self.config.errorReturn,"^/.*$") then
		ngx.header.content_type = "text/html"
		ngx.print(self.config.errorHtmlStr)
		ngx.exit(200)	
	elseif string.match(self.config.errorReturn,"^%d%d%d$") then
		ngx.header.content_type = "text/html"
		ngx.exit(self.config.errorReturn)
	end	
end	

return Guard
