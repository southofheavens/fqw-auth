-- KEYS[1] = zset_key (user_rtk:<userId>)
-- KEYS[2] = new_hset_key (rtk:<hashedRefresh>)
-- ARGV[1] = limit (refresh_tokens_limit)
-- ARGV[2] = ttl (в секундах)
-- ARGV[3] = score (time_since_epoch)
-- ARGV[4] = hashedRefresh
-- ARGV[5] = userAgent
-- ARGV[6] = fingerprint
-- ARGV[7] = userId 

local zset_key = KEYS[1]
local new_hset_key = KEYS[2]
local limit = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local score = tonumber(ARGV[3])
local hashedRefresh = ARGV[4]
local userAgent = ARGV[5]
local fingerprint = ARGV[6]
local userId = ARGV[7]

-- Проверяем текущее количество токенов
local current_count = redis.call('ZCARD', zset_key)

if current_count >= limit then
    -- Получаем самый старый токен (минимальный score)
    local old_tokens = redis.call('ZRANGE', zset_key, 0, 0)
    if #old_tokens > 0 then
        local old_hash = old_tokens[1]
        -- Удаляем его HSET
        redis.call('DEL', 'rtk:' .. old_hash)
        -- Удаляем из ZSET
        redis.call('ZPOPMIN', zset_key)
    end
end

-- Добавляем новый токен в ZSET
redis.call('ZADD', zset_key, score, hashedRefresh)
redis.call('EXPIRE', zset_key, ttl)

-- Создаём HSET с метаданными
redis.call('HSET', new_hset_key,
    'ua', userAgent,
    'fingerprint', fingerprint,
    'user_id', userId
)
redis.call('EXPIRE', new_hset_key, ttl)

return 1