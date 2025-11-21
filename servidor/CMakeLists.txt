cmake_minimum_required(VERSION 3.16)
project(remote_secu_server C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 11)

# Ruta para módulos cmake personalizados
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Incluye la función grpc_generate_cpp()
include(GrpcProtobufGeneration)

# Encuentra protoc y plugin grpc_cpp_plugin instalados por apt
find_program(Protobuf_PROTOC_EXECUTABLE protoc REQUIRED)
find_program(gRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin REQUIRED)

# Busca Protobuf del sistema
find_package(Protobuf REQUIRED)

# Busca gRPC y OpenSSL/Threads
find_package(gRPC REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Archivo proto
set(PROTO_FILE ${CMAKE_CURRENT_SOURCE_DIR}/remote_secu.proto)

# Generar .pb.cc y .grpc.pb.cc
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILE})
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_FILE})

add_executable(remote_secu_server
    secu_remote_server.cpp
    ${PROTO_SRCS}
    ${GRPC_SRCS}
    aes_128_cbc_cmac.c
    aes_128_ctr.c
    aes_128_ecb.c
    kdf.c
    key_nas_deriver.c
    nas_stream_eea0.c
    nas_stream_eea1.c
    nas_stream_eea2.c
    nas_stream_eia1.c
    nas_stream_eia2.c
    rijndael.c
    sha_256_hmac.c
    snow3g.c
    secu_defs.c
    common/utils/LOG/log.c
    common/utils/LOG/lttng-tp.c
    common/utils/LOG/vcd_signal_dumper.c

    common/config/config_cmdline.c
    common/config/config_common.c
    common/config/config_load_configmodule.c
    common/config/config_userapi.c
    common/utils/minimal_stub.c

)

target_include_directories(remote_secu_server PRIVATE
    ${Protobuf_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}/UTILS
    ${CMAKE_CURRENT_SOURCE_DIR}/common/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/common/utils/ds
    ${CMAKE_CURRENT_SOURCE_DIR}/common/utils/LOG
    ${CMAKE_CURRENT_SOURCE_DIR}/common/config
)

# Define MAX_NUM_CCs if it's missing from other headers (fixes nfapi build)
target_compile_definitions(remote_secu_server PRIVATE MAX_NUM_CCs=1)


# Vincular librerías del sistema
target_link_libraries(remote_secu_server
    ${Protobuf_LIBRARIES}
    grpc++
    crypto
    Threads::Threads
    lttng-ust
)
