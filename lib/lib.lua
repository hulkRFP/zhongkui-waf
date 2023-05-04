local config = require "config"
local redisCli = require "redisCli"
local decoder = require "decoder"
local ipUtils = require "ip"
local action = require "action"

local blockIp = action.blockIp
local doAction = action.doAction
local ipairs, pairs = ipairs, pairs
local type = type

local _M = {}

local blackIPLoaded = false

local methodWhiteList = config.get("methodWhiteList")

-- whether or not the regular expression matches on the input
local function matches(input, regex, options, ctx, nth)

    if not options then
        options = "isjo"
    end

    if not nth then
        nth = 0
    end

    return ngx.re.find(input, regex, options, ctx, nth)
end


local function matchRule(ruleTab, str, options)
    if str == nil or next(ruleTab) == nil then
        return false
    end

    for _, t in ipairs(ruleTab) do
        if matches(str, t.rule, options) then
            return true, t
        end
    end

    return false
end


-- Load the ip blacklist in the configuration file and log file to the ngx.shared.dict_blackip or Redis
local function loadIPBlackList()
    if config.isRedisOn then
        for _, ip in ipairs(config.ipBlackList) do
            redisCli.redisBFAdd(ip)
        end
    else
        local blackip = ngx.shared.dict_blackip

        for _, ip in ipairs(config.ipBlackList) do
            blackip:set(ip, 1)
        end
    end
end

-- Returns true if the client ip is in the whiteList,otherwise false
function _M.isWhiteIp()
    if config.isWhiteIPOn then
        local ip = ngx.ctx.ip
        if ip == "unknown" then
            return false
        end

        for _, v in pairs(config.ipWhiteList) do
            if type(v) == 'table' then
                if ipUtils.isSameSubnet(v, ip) then
                    doAction(config.rules.whiteIp, "_", nil, nil)
                    return true
                end
            else
                if ip == v then
                    doAction(config.rules.whiteIp, "-", nil, nil)
                    return true
                end
            end
        end
    end

    return false
end

-- Returns true if the client ip is in the blackList,otherwise false
function _M.isBlackIp()
    if config.isBlackIPOn then
        if not blackIPLoaded then
           loadIPBlackList()
           blackIPLoaded = true
        end

        local ip = ngx.ctx.ip
        if ip == "unknown" then
            return false
        end

        local exists = false

        if ngx.ctx.geoip.isAllowed == false then
            exists = true
        else
            if config.isRedisOn then
                if config.ipBlockTimeout > 0 then
                    exists = redisCli.redisGet("black_ip:" .. ip)
                else
                    exists = redisCli.redisBFExists(ip)
                end
            else
                local blackip = ngx.shared.dict_blackip
                exists = blackip:get(ip)
            end
        end

        if not exists then
            for _, v in pairs(config.ipBlackList_subnet) do
                if type(v) == 'table' then
                    if ipUtils.isSameSubnet(v, ip) then
                        exists = true
                        break
                    end
                end
            end
        end

        if exists then
            doAction(config.rules.blackIp, "-", nil, nil)
        end

        return exists
    end

    return false
end

function _M.isUnsafeHttpMethod()
    local method_name = ngx.req.get_method()

    for _, m in ipairs(methodWhiteList) do
	    if method_name == m then
		    return false
		end
	end

    doAction(config.rules.unsafeMethod, method_name, nil, nil)
    return true
end

function _M.isBlackUA()
    local ua = ngx.var.http_user_agent

    local m, ruleTable = matchRule(config.rules["user-agent"], ua)
    if m then
        doAction(ruleTable, "_", nil, nil)
        return true
    end

    return false
end

-- Nginx 在代理 PHP 请求时，会用到 try_files 机制，导致所有 PHP 请求都会通过 Nginx 内部重定向去调用项目入口文件 /index.php ($uri='/index.php')
-- 这样就导致正常的客户访问也很容易触发 CC 攻击的阈值，所以忽略 uri='/index.php' 的 CC 检查。
function _M.isCC()
    if config.isCCDenyOn then
        local uri = ngx.var.uri
        if uri == '/index.php' then
            return false
        end

        local ip = ngx.ctx.ip
        local token = ngx.md5(ip .. uri)
        local ccSeconds = config.ccSeconds
        local ccCount = config.ccCount
        local m, ruleTable = matchRule(config.rules.cc, uri)

        if m then
            ccSeconds = ruleTable.ccSeconds
            ccCount   = ruleTable.ccCount
            ruleTable.ruleType = "cc"
        else
            ruleTable = {ruleType = "cc", rule = "cc", action = "DENY"}
        end

        if config.isRedisOn then
            local prefix = "cc_req_count:"
            local count = redisCli.redisGet(prefix .. token)
            if not count then
                redisCli.redisSet(prefix .. token, 1, ccSeconds)
            elseif tonumber(count) > ccCount then
		--doAction(ruleTable, "_", nil, 503)
                doAction(ruleTable, count, nil, 503)
                blockIp(ip, "isCC")
                return true
            else
                redisCli.redisIncr(prefix .. token, ccSeconds)
            end
        else
            local limit = ngx.shared.dict_cclimit
            local count,_ = limit:get(token)
            if not count then
                limit:set(token, 1, ccSeconds)
            elseif count > ccCount then
                doAction(ruleTable, count, nil, 503)
                blockIp(ip, "isCC")
                return true
            else
                limit:incr(token, 1, 0, ccSeconds)
            end
        end
    end
    return false
end

-- Returns true if the whiteURL rule is matched, otherwise false
function _M.isWhiteURL()
    if config.isWhiteURLOn then
        local url = ngx.var.uri
        if url == nil or url == "" then
            return false
        end
        local m, ruleTable = matchRule(config.rules.whiteUrl, url)
        if m then
            doAction(ruleTable, "-", nil, nil)
            return true
        end
        return false
    end

	return false
end

-- Returns true if the url rule is matched, otherwise false
function _M.isBlackURL()
    if config.isBlackURLOn then
        local url = ngx.var.uri
        if url == nil or url == "" then
            return false
        end

        local m, ruleTable = matchRule(config.rules.blackUrl, url)
        if m then
            doAction(ruleTable, "-", nil, nil)
            return true
        end
    end
	return false
end


function _M.isEvilArgs()
    local args = ngx.req.get_uri_args()
    if args then
        for _, val in pairs(args) do
            local vals = val
            if type(val) == "table" then
                vals = table.concat(val, ", ")
            end

            if vals and type(vals) ~= "boolean" and vals ~="" then
                local m, ruleTable = matchRule(config.rules.args, decoder.unescapeUri(vals))
                if m then
                    doAction(ruleTable, "-", nil, nil)
                    return true
                end
            end
        end
    end
    return false
end

function _M.isEvilHeaders()
    local referer = ngx.var.http_referer
    if referer and referer ~= "" then
        local m, ruleTable = matchRule(config.rules.headers, referer)
        if m then
            doAction(ruleTable, referer, "headers-referer", nil)
            return true
        end
    end

    local ua = ngx.var.http_user_agent
    if ua and ua ~= "" then
        local m, ruleTable = matchRule(config.rules.headers, ua)
        if m then
            doAction(ruleTable, ua, "headers-ua", nil)
            return true
        end
    end

    return false
end

function _M.isBlackFileExt(ext)
    if ext == nil then
        return false
    end

    local t = config.get("fileExtBlackList")
    for _, v in ipairs(t) do
        if ext == v then
            doAction(config.rules.fileExt, ext, nil, nil)
            return true
        end
    end

    return false
end

function _M.isEvilFile(body)
    local m, ruleTable = matchRule(config.rules.post, body)
    if m then
        doAction(ruleTable, "[" .. body .. "]", "post-file", nil)
        return true
    end

    return false
end

function _M.isEvilBody(body)
    local m, ruleTable = matchRule(config.rules.post, body)
    if m then
        doAction(ruleTable, "[" .. body .. "]", "request-body", nil)
        return true
    end

    return false
end

local function readFile(fileName)
    local f = assert(io.open(fileName, "r"))
    local string = f:read("*all")
    f:close()
    return string
end

function _M.isEvilReqBody()
    if config.isRequestBodyOn then
        local method = ngx.req.get_method()

        local contentType = ngx.var.http_content_type
        local contentLength = tonumber(ngx.var.http_content_length)
        local boundary = nil

        if contentType then
            local bfrom, bto = matches(contentType, "\\s*boundary\\s*=(\\S+)", "isjo", nil, 1)
            if bfrom then
                boundary = string.sub(contentType, bfrom, bto)
            end
        end

        -- form-data
        if boundary then
            local sock, erro = ngx.req.socket()
            local size = 0
            ngx.req.init_body(128 * 1024)  -- buffer is 128KB

            local delimiter = '--' .. boundary
            local delimiterEnd = '--' .. boundary .. '--'

            local body = ''
            local isFile = false

            while size < contentLength do
                if sock ~= nil then
                    local line, err, partial = sock:receive()
                    if line == nil or err then
                        break
                    end

                    if line == delimiter or line == delimiterEnd then
                        if body ~= '' then
                            body = string.sub(body, 1, -2)
                            if isFile then
                                if config.isFileContentOn then
                                    -- 文件内容检查
                                    if _M.isEvilFile(body) then
                                        return true
                                    end
                                end
                                isFile = false
                            else
                                if _M.isEvilBody(body) then
                                    return true
                                end
                            end
                            body = ''
                        end
                    elseif line ~='' then

                        if isFile then
                            if body == '' then
                                local fr = matches(line, "Content-Type:\\s*\\S+/\\S+", "ijo")
                                if fr == nil then
                                    body = body .. line .. '\n'
                                end
                            else
                                body = body .. line .. '\n'
                            end
                        else
                            local from, to = matches(line, [[Content-Disposition:\s*form-data;[\s\S]+filename=["|'][\s\S]+\.(\w+)(?:"|')]], "ijo", nil, 1)

                            if from then
                                local ext = string.sub(line, from, to)

                                if _M.isBlackFileExt(ext) then
                                   return true
                                end

                                isFile = true
                            else
                                local fr = matches(line, "Content-Disposition:\\s*form-data;\\s*name=", "ijo")
                                if fr == nil then
                                    body = body .. line .. '\n'
                                end
                            end
                        end

                    end
                    size = size + string.len(line)
                    ngx.req.append_body(line .. '\n')
                end
            end

            ngx.req.finish_body()

        elseif matches(contentType, "\\s*x-www-form-urlencoded") then
            ngx.req.read_body()
            local args, err = ngx.req.get_post_args()

            if args then
                for _, val in pairs(args) do
                    local vals = val
                    if type(val) == "table" then
                        vals = table.concat(val, ", ")
                    end

                    if vals and type(vals) ~= "boolean" and vals ~= "" then
                        if _M.isEvilBody(vals) then
                            return true
                        end
                    end
                end
            end
        else
            ngx.req.read_body()
            local body_raw = ngx.req.get_body_data()
            if not body_raw then
                local body_file = ngx.req.get_body_file()
                if body_file then
                    body_raw = readFile(body_file)
                end
            end

            if body_raw and body_raw ~= "" then
                if _M.isEvilBody(body_raw) then
                    return true
                end
            end
        end

        return false
    end

    return false
end

function _M.isEvilCookies()
    local cookie = ngx.var.http_cookie
    if config.isCookieOn and cookie then
        local m, ruleTable = matchRule(config.rules.cookie, cookie)
        if m then
            doAction(ruleTable, "-", nil, nil)
            return true
        end
    end

    return false
end

return _M
