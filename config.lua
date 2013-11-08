local Config = {

-----------------全局设置---------------

--自动防攻击，可选为On或者Off,On表示开启触发匹配模块规则（除cc攻击过滤模块）attackTimes次后自动封IP。
autoDeny = "Off",

--设置字典名称，一般不需要修改。
dictName = "guard_dict",

--可选值为single,multiple
--如果有多台nginx在前端并列防攻击，需要设置guardMode的值为multiple，因为需要保持多台nginx生成的key可以在任意一台验证.
--如果设置为multiple后，使用的key将是下面randomKey的值，所以建议做一个定时任务，通过管理接口定时修改randomKey的值
guardMode = "single",

--设置用于生成随机cookie或者随机js跳转代码的key
--key至少为10位(包括数字和字母)，务必要修改此值，要不可能防御失效.
randomKey = "UYS65ws8KQ",

--设置允许访问管理配置变量的接口的ip，值为正则表达式
setDictAllowIP = "^127.0.0.1$",

--设置字典过期时间,单位为秒
--此设置是对开启自动防攻击功能时用来存储攻击次数（attackTimes）的过期时间。
--仅当autoDeny = "On"时有效,对cc攻击过滤模块无效.
dictExpiresTime = 60,

--设置在dictExpiresTime攻击次数超过attackTimes时，添加到黑名单,黑名单过期时间为denySeconds的值.
--仅当autoDeny = "On"时有效,对cc攻击过滤模块无效.
attackTimes = 3,

--设置攻击次数超过黑名单有效时间.
--仅当autoDeny = "On"时有效,对cc攻击过滤模块无效.
denySeconds = 300,

--只对此扩展文件防护.多个扩展文件以|分隔.
--如php|jsp,此设置表示所有模块只对扩展名为php或者jsp的请求过滤，如静态html,git,png就忽略。
fileExtensionProtect = "php",

--当被认定为攻击时返回的信息，可选值为返回的状态码(如403,500,444),
--或者是返回错误页面,如errorReturn = "/data/waf/errorPage.html"
errorReturn = 403,

--如果nginx在后端,有可能需要设置值为请求头的key名来获取客户端真实IP,如X-Real-IP"。
--如果nginx在前端，则此值不要设置，前面的--表示注释。
--realIPViaHeader = "X-Real-IP",

--设置识别客户的方法,默认以cookie识别
--可选值为ip和cookie.
--cookie可以避免误伤许多人共享一个ip上网的情况.
clientIdentify = "cookie",

-----------------ip白名单设置-------------------
--ip白名单开关
ipWhiteModule = "Off",

--ip白名单文件地址,每行一个ip,支持通配符 ，如192.168.0.*
ipWhiteListPath = "/data/waf/ip_white_list",

----------------ip黑名名设置-------------------
--ip黑名单开关
ipBlackModule = "Off",

--ip黑名单文件地址,每行一个ip,支持通配符 ，如192.168.0.*
ipBlackListPath = "/data/waf/ip_black_list",


-----------------日志设置------------------------


--是否记录攻击信息，可选为On(开启),Off(关闭)
logModule = "On",

--输出debug日志,用于调试http-guard
logDebug = "Off",

--只对特定客户端ip的请求输出开启debug,debug信息会输出到nginx的错误日志文件。
--如果不设置，则对所有请求输出debug
--clientIPDebug = "192.168.0.2",

--攻击日志的保存位置
logSavePath = "/data/waf/attack_log",

---------------GET过滤设置---------------

--GET过滤模块开关。可选为On(开启),Off(关闭)
getFilterModule = "On",

--设置匹配Get请求的正则表达式的文件地址。
--建议每行一条规则，每条规则为一条正则表达式，这些规则用来匹配完整的url，如www.centos.bz/http-guard/
getUrlPatternPath = "/data/waf/get_url_pattern_rule",

--------------POST白名单设置----------------
--POST白名单开关，可选为On(开启),Off(关闭)
postWhiteModule = "Off",

--设置post白名单url列表的正则表达式文件地址.
--每行一条规则,每条规则为一条正则表达式，这些规则用来匹配完整的url，如www.centos.bz/post.php
postWhiteUrlPath = "/data/waf/post_white_url",

-------------POST过滤模块设置--------------
--POST模块总开关，可选为On(开启),Off(关闭)
postFilterModule = "On",

--过滤特定扩展名上传的开关，可选为On(开启),Off(关闭)
uploadExtensionDeny = "On",

--设置禁止上传哪些后缀的文件,如php
--多个后缀文件以|分隔，如php|jsp
fileExtension = "php",

--设置匹配post表单内容的正则表达式文件地址.
--每行一条规则,每条规则为一条正则表达式，这些规则用来匹配post的内容
postPatternPath = "/data/waf/post_pattern_rule",

-----------cookie过滤设置--------------
--cookie过滤开关。可选为On(开启),Off(关闭)
cookieFilterModule = "Off",

--cookie过滤规则文件
--每行一条规则,每条规则为一条正则表达式，这些规则用来匹配cookie的值
cookiePatternPath = "/data/waf/cookie_pattern_rule",

-------------------CC攻击过滤设置----------------

--cc攻击过滤模块开关。可选为On(开启),Off(关闭)
ccAttackFilterModule = "On",

--设置在60秒钟内访问次数超过urlVisitTimes则被判定为cc攻击.
urlVisitTimes = 120,

--设置被判定为cc攻击后，封锁IP的时间,单位秒.
CCBlackDicExpiresTime = 600,

--JS跳转验证防cc开关。可选为On或者Off
--当开启时，每来一个请求，首先会生效一个随机数，并存入字典，然后马上返回一段js代码。
--如<script>window.location.href='http://www.centos.bz/hello.php?cckey=168888';</script>
--当跳转时，http-guard会取得cckey值，即168888，再跟字典里的值比较，比如相等，就标记验证通过，下次请求再来时直接放行
--否则再返回js跳转代码。
jsJumpCodeSend = "Off",

--js跳转验证通过后白名单的时间
jsVerifyWhiteTime = 600,

--设置对此文件中的url进行js跳转验证.
--每行一条规则,每条规则为一条正则表达式，这些规则用来匹配请求的url，然后决定是否发送js跳转代码
--当jsJumpCodeSend = "On"时有效。
jsJumpProtectUrlPath = "/data/waf/cc_attack_protect_url",
}
return Config
