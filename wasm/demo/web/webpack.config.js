const path = require('path');
const WasmPackPlugin = require("@wasm-tool/wasm-pack-plugin");
const CopyWebpackPlugin = require("copy-webpack-plugin");

module.exports = {
    entry: './bootstrap.js',
    output: {
        path: path.resolve(__dirname, "dist"),
        filename: "bootstrap.js",
    },
    plugins: [
        new CopyWebpackPlugin(['index.html']),
        new WasmPackPlugin({
            crateDirectory: path.resolve(__dirname, ".")
        }),
    ],
    mode: 'development',
    experiments: {
        asyncWebAssembly: true
   }
};
