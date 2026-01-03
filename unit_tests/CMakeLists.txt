set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(
  pliney_transport
  pliney_transport.cpp
  ${CMAKE_SOURCE_DIR}/libpliney/src/constants.cpp
)
target_link_libraries(
  pliney_transport
  GTest::gtest_main
)
target_include_directories(pliney_transport PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(pliney_transport PRIVATE ${EXTRA_DEFINITIONS})

include(GoogleTest)
gtest_discover_tests(pliney_transport)
