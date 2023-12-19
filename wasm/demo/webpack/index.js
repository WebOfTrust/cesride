// Note that a dynamic `import` statement here is required due to
// webpack/webpack#6615, but in theory `import { greet } from './pkg';`
// will work here one day as well!
import * as cesride from 'cesride-wasm';

document.write(`
<style>
  body {
    background-color: black;
    color: #cccccc;
  }
</style>
`)

let dts = "2020-08-22T17:50:09.988921+00:00";
let dater = new cesride.Dater(dts, undefined, undefined, undefined, undefined, undefined);

const icp = {
  "v": "KERI10JSON00015a_",
  "t": "icp",
  "d": "EBAjyPZ8Ed4XXl5cVZhqAy7SuaGivQp0WqQKVXvg7oqd",
  "i": "BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI",
  "s": "0",
  "kt": "1",
  "k": [
    "BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI"
  ],
  "nt": "0",
  "n": [],
  "bt": "2",
  "b": [
    "BC9Df6ssUZQFQZJYVUyfudw4WTQsugGcvVD_Z4ChFGE4",
    "BEejlxZytU7gjUwtgkmNKmBWiFPKSsXjk_uxzoun8dtK"
  ],
  "c": [],
  "a": []
}

const raw = new TextEncoder().encode(JSON.stringify(icp))
const serder = cesride.Serder.new_with_raw(raw)
console.log(serder.saider().qb64())

document.write("<p>Date:</p>");
document.write("<code>")
document.write("dts: " + dater.dts() + "<br/>");
document.write("dtsb: " + dater.dtsb() + "<br/>");
document.write("code: " + dater.code() + "<br/>");
document.write("size: " + dater.size() + "<br/>");
document.write("raw: " + dater.raw() + "<br/>");
document.write("qb64: " + dater.qb64() + "<br/>");
document.write("qb64b: " + dater.qb64b() + "<br/>");
document.write("qb2: " + dater.qb2() + "<br/>");
try {
  dater = new cesride.Dater("asdf", undefined, undefined, undefined, undefined, undefined);
  document.write("Wrong dater: " + dater.dts() + "<br/>");
} catch (error) {
  document.write("Error: " + error + "<br/>");
  document.write("Error name: " + error.name + "<br/>");
  document.write("Error message: " + error.message + "<br/>");
}
document.write("</code>")
