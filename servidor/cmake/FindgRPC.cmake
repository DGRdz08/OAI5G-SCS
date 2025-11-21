find_path(gRPC_INCLUDE_DIR grpc/grpc.h
  PATHS /usr/include /usr/local/include
)

find_library(gRPC_GRPCPP_LIBRARY
  NAMES grpc++
  PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
)

if (gRPC_INCLUDE_DIR AND gRPC_GRPCPP_LIBRARY)
  set(gRPC_FOUND TRUE)
  set(gRPC_LIBRARIES ${gRPC_GRPCPP_LIBRARY})
else()
  set(gRPC_FOUND FALSE)
endif()

if (gRPC_FOUND)
  message(STATUS "Found gRPC: ${gRPC_GRPCPP_LIBRARY}")
else()
  message(FATAL_ERROR "gRPC not found")
endif()
