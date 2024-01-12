In order to generate the library, you must clone the repo
- https://github.com/jibsen/brieflz

And use these commands.

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBRIEFLZ_BUILD_SHARED=ON ..
cmake --build . --config Release
```
The [CMakeLists](CMakeLists.txt) was modified to create the library.