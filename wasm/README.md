# WASM FFI for CESRIDE

### How to build with wasm-pack
Install wasm-pack from https://rustwasm.github.io/wasm-pack/installer/ and then

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

### Run demo in Browser
```
cd demo/web
yarn install
yarn serve
```

and then visit http://localhost:8080 in a browser should run the example!
