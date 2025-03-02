@echo off
echo Building project...
mkdir build
cd build
cmake ..
cmake --build . --config Release

echo Running main.exe...
..\bin\main.exe

pause