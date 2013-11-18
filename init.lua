local Config = require("config")
--初始化字典
Dict = ngx.shared[Config.dictName]

--解析文件到正则表达式
local function parseRuleFile(path,key)
	local list = ''
	local rfile = assert(io.open(path,'r'))
	for line in rfile:lines() do
		if not (string.match(line,"^ *$")) then
			list = list.."|"..line
		end
	end
	list = string.gsub(list,"^%|",'')
	Config[key] = list
	rfile:close()
end

--解析ip文件
local function parseIPFile(path,key)
        local list = ''
        local rfile = assert(io.open(path,'r'))
        for line in rfile:lines() do
                if not (string.match(line,"^ *$")) then
			line = string.gsub(line,"%.","\\.")
			line = string.gsub(line,"%*",".*")
			line = string.gsub(line,"$","%$")
                        list = list.."|"..line
                end
        end
        list = string.gsub(list,"^%|",'')
		Config[key] = list  
        rfile:close()
end

----载入白名单和黑名单列表
if string.lower(Config.ipWhiteModule) == "on" then
	parseIPFile(Config.ipWhiteListPath,"whiteIPList")
end
if string.lower(Config.ipBlackModule) == "on" then
	parseIPFile(Config.ipBlackListPath,"blackIPList")
end

--载入错误页面到内存
if string.match(Config.errorReturn,"^/") then
	local rfile = assert(io.open(Config.errorReturn,"r"))
	local errorHtmlStr = rfile:read("*all")
	Config.errorHtmlStr = errorHtmlStr
	rfile:close()
end

--获取匹配需要保护扩展的正则
Config.extensionProtectReg = "^/.*\\.("..Config.fileExtensionProtect..")$"

--生成一个随机数，用于加密cookie，防止伪造
if Config.guardMode == "single" then
	math.randomseed( os.time() )
	local Random = math.random(100000,999999)
	local randomKey = ngx.md5(Random)
	Config.randomKey = randomKey
elseif Config.guardMode == "multiple" then
	--do nothing
else
	ngx.log(ngx.ERR,"Guard mode "..Config.guardMode.." is invalid")
end	


--解析get过滤规则配置文件
if string.lower(Config.getFilterModule) == "on" then
	parseRuleFile(Config.getUrlPatternPath,"getRule")
	if string.match(Config.getRule, "^ *$") then ngx.log(ngx.ERR,Config.getUrlPatternPath," can not be empty.") end
end

--解析post过滤规则配置文件
if string.lower(Config.postFilterModule) == "on" then
        parseRuleFile(Config.postPatternPath,"postRule")
    if string.match(Config.postRule, "^ *$") then ngx.log(ngx.ERR,Config.postPatternPath," can not be empty.") end
end	

--解析cookie过滤规则配置文件
if string.lower(Config.cookieFilterModule) == "on" then
        parseRuleFile(Config.cookiePatternPath,"cookieRule")
	if string.match(Config.cookieRule, "^ *$") then ngx.log(ngx.ERR,Config.cookiePatternPath," can not be empty.") end
end

--解析useragent过滤规则配置文件
if string.lower(Config.useragentFilterModule) == "on" then
        parseRuleFile(Config.useragentPatternPath,"useragentRule")
	if string.match(Config.useragentRule, "^ *$") then ngx.log(ngx.ERR,Config.useragentPatternPath," can not be empty.") end
end

--解析需要通过js跳转防cc的url规则配置文件
if string.lower(Config.jsJumpCodeSend) == "on" then
        parseRuleFile(Config.jsJumpProtectUrlPath,"jsJumpRule")
if string.match(Config.jsJumpRule, "^ *$") then ngx.log(ngx.ERR,Config.jsJumpProtectUrlPath," can not be empty.") end
end

--解析post白名单规则配置文件
if string.lower(Config.postWhiteModule) == "on" then
	parseRuleFile(Config.postWhiteUrlPath,"postWhiteRule")
	if string.match(Config.postWhiteRule, "^ *$") then ngx.log(ngx.ERR,Config.postWhiteUrlPath," can not be empty.") end
end	

--变量存放到字典
for k, v in pairs(Config) do
	Dict:set(k, v)
end	
