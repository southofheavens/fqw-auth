local zset_key = KEYS[1]
local hset_key = KEYS[2]
redis.call('ZREM', zset_key, ARGV[1])
redis.call('DEL', hset_key)
return 1