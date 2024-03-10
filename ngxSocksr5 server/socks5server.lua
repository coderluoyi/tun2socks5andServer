local _M = {_VERSION = '0.0.1'}

local dns_resolver = require "resty.dns.resolver"
local dnsr = dns_resolver : new {
    nameservers = {"114.114.114.114", {"8.8.8.8", 53}},
    retrans = 5,    -- 5 retransmissions on receive timeout
    timeout = 2500, -- 2.5 sec
}

local bit = require "bit"
local char = string.char
local byte = string.byte
local sub = string.sub
local fmt = string.format

local ngx_log = ngx.log
local ngx_exit = ngx.exit
local ERR = ngx.ERR
local ERROR = ngx.ERROR
local DEBUG = ngx.DEBUG

-- magic number
local SOCKS5_VER = 0x05
local NO_AUTHENCATION = 0x00

local no_auth_method = char(SOCKS5_VER, NO_AUTHENCATION)

local TCP_CONNECTION = 0x01
local RESERVED = 0x00
local IPV4 = 0x01
local DOMAIN_NAME = 0x03
local IPV6 = 0x04

local NONE_INET_ADDR = "\x00\x00\x00\x00\x00\x00"

local SUCCEEDED = 0x00
local CMD_NOT_SUPPORTED = 0x07

local function safe_close(sock)
    if sock.close then
        pcall(sock.close)
    end
end

local function receive_methods(sock)
    --[[ 
        ver,      0x05    | SOCKS5_VER
        nmethods, #byte 1
        methods,  #byte (nmethods)
    --]]
    local data, err = sock:receive(2)
    if not data then
        ngx_exit(ERROR)
        return nil, err
    end
    
    local ver = byte(data, 1)
    local nmethods = byte(data, 2)

    local methods, err = sock:receive(nmethods)
    if not methods then
        ngx_exit(ERROR)
        return nil, err
    end

    return {
        ver = ver,
        nmethods = nmethods,
        methods = methods
    }, nil
end


local function send_no_auth_method(sock)
    --[[
        ver,    0x05 | SOCKS5_VER
        method, 0x00 | NO_AUTHENCATION
    --]]
    return sock:send(no_auth_method)
end


local function receive_requests(sock)
    --[[
        ver,  0x05    | SOCKS5_VER
        cmd,  #byte 1
        rsv,  0x00    | RESERVED
        atyp, #byte 1
        addr, 可变长
        port, #byte 2
    --]]
    local data, err = sock:receive(4)
    if not data then
        ngx_log(ERR, "function-receive_requests header: ", err)

        return nil, err
    end

    local ver = byte(data, 1)
    local cmd = byte(data, 2)
    local rsv = byte(data, 3)
    local atyp = byte(data, 4)

    local addr_len = 0
    if atyp == IPV4 then
        addr_len = 4

    elseif atyp == DOMAIN_NAME then
        local dn_len, err = sock:receive(1)
        if not dn_len then
            ngx_log(ERR, "function-receive_requests dn_len: ", err)

            return nil, err
        end

        addr_len = byte(dn_len, 1)

    elseif atyp == IPV6 then
        addr_len = 16

    else
        ngx_log(ERR, "function-receive_requests atyp: ", err)

        return nil, "atyp unknown: " .. atyp
    end

    local data, err = sock:receive(addr_len + 2)
    if err then
        ngx.log(ERR, "function-receive_requests dst_addr: ", err)

        return nil, err
    end

    local addr = sub(data, 1, addr_len)
    local port_high = byte(data, addr_len + 1)
    local port_low = byte(data, addr_len + 2)
    local port = port_high * 256 + port_low

    return {
        ver = ver,
        cmd = cmd,
        rsv = rsv,
        atyp = atyp,
        addr = addr,
        port = port
    }, nil
end


local function send_replies(sock, rep, atyp, addr, port)
    --[[
        ver,  0x05    | SOCKS5_VER
        rep,  #byte 1
        rsv,  0x00    | RESERVED
        atyp, #byte 1
        addr, 可变
        port, #byte 2
    --]]
    local replies = {char(SOCKS5_VER)}
    replies[2] = char(rep)
    replies[3] = char(RESERVED)

    if atyp and addr and port then
        replies[4] = atyp
        replies[5] = addr
        replies[6] = port
    else
        replies[4] = char(IPV4)
        replies[5] = NONE_INET_ADDR
    end

    return sock:send(replies)
end

local function recur_dnsr(dn, deep)
    if deep == 0 then
        return dn
    end

    ngx_log(DEBUG, "DNS resolve: deep - ", deep, " domain name: ", dn)
    local answers, err, tri = dnsr:query(dn, nil, {})
    if not answers then
        ngx_log(ERR, "dns resolver err: ", err, "dn: ", dn)
        return dn
    end

    local ipv4_exist = false
    local cname = nil
    local ipv4 = nil
    for i, ans in ipairs(answers) do
        if ans.type == dnsr.TYPE_A then -- 只使用 ipv4 ans
            ipv4 = ans.address
            ipv4_exist = true
            break
        elseif ans.type == dnsr.TYPE_CNAME then
            if cname == nil then
                cname = ans.address
            end
        end
    end

    if ipv4_exist == true then
        return ipv4
    elseif cname == nil then
        return dn
    else
        return recur_dnsr(cname, deep - 1)
    end
end

local function stringify_addr(atyp, addr)
    local dst = addr
    if atyp == IPV4 then
        dst = fmt("%d.%d.%d.%d", byte(addr, 1), byte(addr, 2), byte(addr, 3), byte(addr, 4))
    elseif atyp == IPV6 then
        dst = fmt("[%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X]", 
            byte(addr, 1), byte(addr, 2),
            byte(addr, 3), byte(addr, 4),
            byte(addr, 5), byte(addr, 6),
            byte(addr, 7), byte(addr, 8),
            byte(addr, 9), byte(addr, 10),
            byte(addr, 11), byte(addr, 12),
            byte(addr, 13), byte(addr, 14),
            byte(addr, 15), byte(addr, 16)
        )
    elseif atyp == DOMAIN_NAME then
        --[[ 手动解析 ipv4, 
            1. 可控的 timeout; 
            2. 避免 ipv6 使用不了
            3. 递归解析
                3-1. 递归的层数可控
        --]]
        dst = recur_dnsr(addr, 2)
    end

    return dst
end

local function sock_send(data, sock, info)
    local ok, err = sock:send(data)
    if err then
        ngx_log(ERR, "pipe send the dst get error: ", err, info)
        return err
    end
    return nil
end

function _M.run(timeout, conn_timeout)
    -- 客户端 tcp
    local downsock, err = assert(ngx.req.socket(true))
    if not downsock then
        ngx_log(ERR, "failed to get request socket: ", err)

        return ngx_exit(ERROR)
    end

    downsock:settimeout(timeout)

    -- 协商方法
    local negotiation, err = receive_methods(downsock)
    if err then
        ngx_log(ERR, "receive methods err: ", err)
        safe_close(downsock)

        return ngx_exit(ERROR)
    end

    if negotiation.ver ~= SOCKS5_VER then
        ngx_log(DEBUG, "only support version: ", SOCKS5_VER)
        safe_close(downsock)

        return ngx_exit(ERROR)
    end

    local ok, err = send_no_auth_method(downsock)
    if err then
        ngx_log(ERR, "send method error: ", err)
        safe_close(downsock)

        return ngx_exit(ERROR)
    end

    -- 协商代理
    local requests, err = receive_requests(downsock)
    if err then
        ngx_log(ERR, "send request error: ", err)
        safe_close(downsock)
        
        return ngx_exit(ERROR)
    end

    if requests.cmd ~= TCP_CONNECTION then
        ngx_log(DEBUG, "only support cmd: ", TCP_CONNECTION)
        local ok, err = send_replies(downsock, CMD_NOT_SUPPORTED)
        if err then
            ngx_log(ERR, "send replies CMD-Not-Supported error: ", err)
        end
        safe_close(downsock)

        return ngx_exit(ERROR)
    end

    -- 建立服务端tcp, 协程 管道转发
    local upsock = ngx.socket.tcp()
    upsock:settimeout(conn_timeout)

    local addr = stringify_addr(requests.atyp, requests.addr)
    local ok, err = upsock:connect(addr, requests.port)
    if err then
        ngx_log(ERR, "connect request " .. requests.addr ..
            ":" .. requests.port .. " error: ", err)
        safe_close(downsock)

        return ngx_exit(ERROR)
    end
    
    addr = fmt("%s:%d", addr, requests.port)
    ngx_log(DEBUG, addr)

    upsock:settimeout(timeout)

    local ok, err = send_replies(downsock, SUCCEEDED)
    if err then
        ngx_log(ERR, "send replies error: ", err)
        safe_close(downsock)
        safe_close(upsock)

        return ngx_exit(ERROR)
    end

    local is_close = false

    local pipe = function(src, dst, info)
        ngx_log(DEBUG, "socks5 handShake ok - pipe: ", info)

        while true do
            if is_close == true then
                break
            end

            local data, err, partial = src:receive(8192)
            if not data then
                if partial then
                    err = sock_send(partial, dst, info)
                    if err == 'closed' then
                        ngx_log(ERR, "right/dst connection closed @send ", info)
                        break
                    end
                end
                
                -- ngx_log(ERR, "catch err: ", err)

                if err == 'closed' then
                    ngx_log(ERR, "left/src connection closed @receive ", info)
                    break
                -- elseif err ~= 'timeout' then
                --    ngx_log(ERR, "error receiving data from ", src_addr, ": ", err)
                --    break
                end
            else
                err = sock_send(data, dst, info)
                if err == 'closed' then
                    ngx_log(ERR, "right/dst connection closed @send ", info)
                    break
                end
            end
        end
    
        safe_close(src)
        safe_close(dst)
        is_close = true
    end

    local co_updown = ngx.thread.spawn(pipe, upsock, downsock, addr .. " -> client")
    local co_downup = ngx.thread.spawn(pipe, downsock, upsock, "client -> " .. addr)

    ngx.thread.wait(co_updown)
    ngx.thread.wait(co_downup)
end

_M.run(200, 1800)
