// Note that a dynamic `import` statement here is required due to
// webpack/webpack#6615, but in theory `import { greet } from './pkg';`
// will work here one day as well!
const wasm = import('cesride-wasm');

wasm
  .then(cesride => {
    date = cesride.Dater.new_with_dts(dts = "2020-08-22T17:50:09.988921+00:00");
    document.write("<p>Date:</p>");
    document.write("dts: " + date.dts() + "<br/>");
    document.write("dtsb: " + date.dtsb() + "<br/>");
    document.write("code: " + date.code() + "<br/>");
    document.write("size: " + date.size() + "<br/>");
    document.write("raw: " + date.raw() + "<br/>");
    document.write("qb64: " + date.qb64() + "<br/>");
    document.write("qb64b: " + date.qb64b() + "<br/>");
    document.write("qb2: " + date.qb2() + "<br/>");
    try {
      date = cesride.Dater.new_with_dts(dts = "asdf");
      document.write("Wrong date: " + date.dts() + "<br/>");
    } catch (error) {
      document.write("Error: " + error + "<br/>");
      document.write("Error name: " + error.name + "<br/>");
      document.write("Error message: " + error.message + "<br/>");
    }
  })
  .catch(console.error);
