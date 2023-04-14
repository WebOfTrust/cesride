# WASM FFI for CESRIDE

You can build the FFI with
```
$ wasm-pack build
```

### How to build
Install wasm-pack from https://rustwasm.github.io/wasm-pack/installer/ and then
```
make # Will output modules best-suited to be bundled with webpack
WASM_TARGET=nodejs make # Will output modules that can be directly consumed by NodeJS
WASM_TARGET=web make # Will output modules that can be directly consumed in browser without bundler usage
```

### How to build with wasm-pack build
```
wasm-pack build # Will output modules best-suited to be bundled with webpack
wasm-pack build --target=nodejs # Will output modules that can be directly consumed by NodeJS
wasm-pack build --target=web # Will output modules that can be directly consumed in browser without bundler usage
```

### Run NodeJS demo
```
cd demo/node
yarn install
yarn start
```

### Run demo шт Browser
```
cd demo/web
yarn install
yarn serve
```

and then visit http://localhost:8080 in a browser should run the example!
