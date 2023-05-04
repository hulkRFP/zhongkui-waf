local logger = require "logger"

local loggers = {}

local _M = {}

function _M.getLogger(logPath, host, rolling, joining)
    local hostLogger = loggers[host]
    if not hostLogger then
        hostLogger = logger:new(logPath, host, rolling, joining)
        loggers[host] = hostLogger
    end
    return hostLogger
end


return _M
