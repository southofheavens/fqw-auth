project('fqw-auth', 'cpp')

cpp = meson.get_compiler('cpp')

devkit_dep = dependency('fqw-devkit',
  fallback: ['fqw-devkit', 'devkit_dep'],
  required: true
)

poco_foundation = cpp.find_library('PocoFoundation', required: true)
poco_util = cpp.find_library('PocoUtil', required: true)
poco_net = cpp.find_library('PocoNet', required: true)
poco_json = cpp.find_library('PocoJSON', required: true)
poco_data = cpp.find_library('PocoData', required: false) 
poco_data_postgresql = cpp.find_library('PocoDataPostgreSQL', required: false)
poco_jwt = cpp.find_library('PocoJWT', required: true)
poco_redis = cpp.find_library('PocoRedis', required: true)

pq = cpp.find_library('pq', required: true)
sodium = cpp.find_library('sodium', required: true)
ssl = cpp.find_library('ssl', required: true)
crypto = cpp.find_library('crypto', required: true)

all_deps = [
  poco_foundation,
  poco_util,
  poco_net,
  poco_json,
  poco_jwt,
  poco_redis,
  pq,
  sodium,
  ssl,
  crypto,
  devkit_dep
]

if poco_data.found()
  all_deps += poco_data
endif

if poco_data_postgresql.found()
  all_deps += poco_data_postgresql
endif

src_files = [
  'src/main.cpp',
  'src/Handlers.cpp',
  'src/Utils.cpp'
]

include_dirs = [
  'src',
  'subprojects'
]

executable('fqw-auth',
  src_files,
  include_directories: include_dirs,
  dependencies: all_deps,
  cpp_args: ['-std=c++20']
)

# DYLD_LIBRARY_PATH=/usr/local/lib ./build/fqw-auth