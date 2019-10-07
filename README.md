# ZUnTracer-AFL
Zipr + UnTracer-AFL

## INSTALLATION
#### 1. Download and build the ZAFL Umbrella and its submodules 
```
git clone --recurse-submodules git@git.zephyr-software.com:allnp/zafl_umbrella.git
cd zafl_umbrella
. set_env_vars
./get_packages.sh
./build-all.sh
cd $ZAFL_HOME/zipr_umbrella
./postgres_setup.sh
```

#### 2. Download ZUnTracer-AFL (this repo)
```
git clone https://github.com/FoRTE-Research/ZUnTracer-AFL
```

#### 3. Configure UnTracer's environment variables
```
export ZAFL_HOME=''
export ZEST_RUNTIME=$ZAFL_HOME/zest_runtime/lib
export ZEST32_RUNTIME=$ZAFL_HOME/zipr_umbrella/zest_runtime/lib32:
export ZEST64_RUNTIME=$ZAFL_HOME/zipr_umbrella/zest_runtime/lib64:

export ZUNTRACER_AFL_PATH=''

export LD_LIBRARY_PATH=$ZUNTRACER_AFL_PATH:$ZEST_RUNTIME:$ZEST32_RUNTIME:$ZEST64_RUNTIME
export PATH=$PATH:$ZUNTRACER_AFL_PATH
```
Make sure to also `cd $ZAFL_HOME` and run `. set_env_vars`!

#### 4. Build ZUnTracer-AFL
Run the following commands:
```
make clean && make all
```

## USAGE
