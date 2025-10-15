#!/bin/bash

#colcon build --cmake-args -DSECURITY=on -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_STANDARD=17 --packages-select=image_tools
#colcon build --cmake-args -DSECURITY=on -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_STANDARD=17
#colcon build --cmake-clean-cache --cmake-args -DCMAKE_BUILD_TYPE=Debug -DSECURITY=on -DCMAKE_CXX_STANDARD=17  
#colcon build --cmake-clean-cache --cmake-args -DCMAKE_BUILD_TYPE=Debug -DSECURITY=on -DCMAKE_CXX_STANDARD=17 --packages-up-to=fastrtps

#colcon build --cmake-args -DCMAKE_BUILD_TYPE=Debug -DSECURITY=ON -DCMAKE_CXX_STANDARD=17 --packages-up-to=fastrtps --cmake-clean-cache 

# colcon build --symlink-install --cmake-args -DOPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR -DSECURITY=ON --packages-select fastrtps --cmake-clean-cache
colcon build --symlink-install --cmake-args -DCMAKE_BUILD_TYPE=Debug -DOPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR -DSECURITY=ON --packages-select fastrtps --cmake-clean-cache
source ./install/setup.bash
