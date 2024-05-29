# WASM FFI for CESRIDE

### How to build with wasm-pack
Install wasm-pack from https://rustwasm.github.io/wasm-pack/installer/ and then

```
wasm-pack build [--target=bundler] # Will output modules best-suited to be bundled with webpack (Ecmascript modules, ESM)
wasm-pack build --target=nodejs # Will output modules that can be directly consumed by NodeJS (CommonJS modules, CJS)
wasm-pack build --target=web # Will output modules that can be directly consumed in browser without bundler usage (ESM module with extra scaffolding for use standalone)
```

Passing `--dev` to the above commands will give extra debugging info and makes the compilation faster at the cost of a slightly bigger wasm module.

## Demos

These are examples of how to use the package in various flavors

### CJS demo (--target=nodejs)
```
wasm-pack build --target=nodejs # Will output modules that can be directly consumed by NodeJS (CommonJS modules, CJS)
cd demo/node
yarn install
yarn start
```

### Browser demo (--target=web)
```
wasm-pack build --target=web # Will output modules that can be directly consumed in browser without bundler usage (ESM module with extra scaffolding for use standalone)
cd demo/web
python -m http.server # or another web server of choice serving index.html which should load the pkg automatically as a js module. See index.html for example of scaffolding necessary to get the wasm to load.
```

### ESM demo (--target=bundler)
```
wasm-pack build # Will output modules best-suited to be bundled with webpack (Ecmascript modules, ESM)
cd demo/webpack
yarn install
yarn serve
# and then visit http://localhost:8080 in a browser should run the example!
```

## Integration with signify-ts
Currently only the CJS artifact works when integrating with signify-ts (maybe someone better with the various nonsense js import systems can figure it out).  The steps are as follows:
1. Build cesride in the regular fashion.
2. cd to the wasm directory and use `wasm-pack build --target=nodejs` to build your wasm package
3. Add the `pkg/` directory as a dependency to signify-ts
4. The cesride-wasm artifact should now be callable by tests and signify-ts.

Its also nice to note that wasm-pack produces a types file in pkg/ that describes the complete interface.  Something like `cesride_wasm.d.ts`.  Useful for debugging when making changes to this crate.

## Testing
You can test the Rust interface wrappers using rstest as long as they're vanilla Rust but as soon as you start having dependencies on anything that requires wasm-pack it'll be better to use wasm-bindgen-test crate to test.  Those tests are in the `tests` directory and must remain in the base wasm crate for wasm-bindgen-test to work.

That crate is actually just the runner, `wasm-pack test --target=<{node,chrome,firefox,safari}>` is how the tests are run and by default they run in --headless browsers.  Some of the targets may not work if you don't have the correct browser drivers installed on your testing instance or docker container.  Installing those is out of scope for this README.

To add a test, import from the cesride\_wasm crate and test it by using the the macro #[wasm\_bindgen\_test] on all the things you'd like to test.  Async tests are also available.  More info can be found (here)[https://rustwasm.github.io/wasm-bindgen/wasm-bindgen-test/index.html]
