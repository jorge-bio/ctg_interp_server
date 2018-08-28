cmake_minimum_required(VERSION 2.6)
project(ctg_interp_server)

add_executable(ctg_interp_server main.c jsmn.c)

install(TARGETS ctg_interp_server RUNTIME DESTINATION bin)
