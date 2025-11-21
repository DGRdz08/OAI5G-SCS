function(grpc_generate_cpp SRCS HDRS)
  if(NOT ARGN)
    message(SEND_ERROR "Error: grpc_generate_cpp() called without any proto files")
    return()
  endif()

  set(_proto_files ${ARGN})

  foreach(_proto ${_proto_files})
    get_filename_component(_abs_file ${_proto} ABSOLUTE)
    get_filename_component(_file_dir ${_abs_file} PATH)
    get_filename_component(_file_we  ${_abs_file} NAME_WE)

    set(_src "${CMAKE_CURRENT_BINARY_DIR}/${_file_we}.grpc.pb.cc")
    set(_hdr "${CMAKE_CURRENT_BINARY_DIR}/${_file_we}.grpc.pb.h")

    add_custom_command(
      OUTPUT "${_src}" "${_hdr}"
      COMMAND ${Protobuf_PROTOC_EXECUTABLE}
      ARGS --grpc_out=${CMAKE_CURRENT_BINARY_DIR}
           --plugin=protoc-gen-grpc=${gRPC_CPP_PLUGIN_EXECUTABLE}
           --proto_path=${_file_dir}
           ${_abs_file}
      DEPENDS ${_abs_file}
    )

    list(APPEND ${SRCS} "${_src}")
    list(APPEND ${HDRS} "${_hdr}")
  endforeach()

  set(${SRCS} ${${SRCS}} PARENT_SCOPE)
  set(${HDRS} ${${HDRS}} PARENT_SCOPE)
endfunction()
