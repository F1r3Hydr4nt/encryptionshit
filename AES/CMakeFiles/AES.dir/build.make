# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.12

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.12.1/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.12.1/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/HON3D/encryptionshit/AES

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/HON3D/encryptionshit/AES

# Include any dependencies generated for this target.
include CMakeFiles/AES.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/AES.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/AES.dir/flags.make

CMakeFiles/AES.dir/AES.cpp.o: CMakeFiles/AES.dir/flags.make
CMakeFiles/AES.dir/AES.cpp.o: AES.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/HON3D/encryptionshit/AES/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/AES.dir/AES.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/AES.dir/AES.cpp.o -c /Users/HON3D/encryptionshit/AES/AES.cpp

CMakeFiles/AES.dir/AES.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/AES.dir/AES.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/HON3D/encryptionshit/AES/AES.cpp > CMakeFiles/AES.dir/AES.cpp.i

CMakeFiles/AES.dir/AES.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/AES.dir/AES.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/HON3D/encryptionshit/AES/AES.cpp -o CMakeFiles/AES.dir/AES.cpp.s

CMakeFiles/AES.dir/main.cpp.o: CMakeFiles/AES.dir/flags.make
CMakeFiles/AES.dir/main.cpp.o: main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/HON3D/encryptionshit/AES/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/AES.dir/main.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/AES.dir/main.cpp.o -c /Users/HON3D/encryptionshit/AES/main.cpp

CMakeFiles/AES.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/AES.dir/main.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/HON3D/encryptionshit/AES/main.cpp > CMakeFiles/AES.dir/main.cpp.i

CMakeFiles/AES.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/AES.dir/main.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/HON3D/encryptionshit/AES/main.cpp -o CMakeFiles/AES.dir/main.cpp.s

# Object files for target AES
AES_OBJECTS = \
"CMakeFiles/AES.dir/AES.cpp.o" \
"CMakeFiles/AES.dir/main.cpp.o"

# External object files for target AES
AES_EXTERNAL_OBJECTS =

AES: CMakeFiles/AES.dir/AES.cpp.o
AES: CMakeFiles/AES.dir/main.cpp.o
AES: CMakeFiles/AES.dir/build.make
AES: CMakeFiles/AES.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/HON3D/encryptionshit/AES/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable AES"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/AES.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/AES.dir/build: AES

.PHONY : CMakeFiles/AES.dir/build

CMakeFiles/AES.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/AES.dir/cmake_clean.cmake
.PHONY : CMakeFiles/AES.dir/clean

CMakeFiles/AES.dir/depend:
	cd /Users/HON3D/encryptionshit/AES && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/HON3D/encryptionshit/AES /Users/HON3D/encryptionshit/AES /Users/HON3D/encryptionshit/AES /Users/HON3D/encryptionshit/AES /Users/HON3D/encryptionshit/AES/CMakeFiles/AES.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/AES.dir/depend
