-- KEYS[1] = user_rtk key (e.g. "user_rtk:123")
-- ARGV[1] = fingerprint
-- ARGV[2] = userAgent

local hashes = redis.call('ZRANGE', KEYS[1], 0, -1)
if not hashes or #hashes == 0 then
    return nil
end

for i = 1, #hashes do
    local hash = hashes[i]
    local hkey = 'rtk:' .. hash
    local stored_fp = redis.call('HGET', hkey, 'fingerprint')
    local stored_ua = redis.call('HGET', hkey, 'ua')

    if stored_fp == ARGV[1] and stored_ua == ARGV[2] then
        return hash
    end
end

return nil