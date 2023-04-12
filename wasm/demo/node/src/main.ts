import { Dater } from "cesride-wasm";

function main() {
    const date = Dater.new_with_dts("2020-08-22T17:50:09.988921+00:00");
    console.log("<p>Date:</p>");
    console.log("dts: " + date.dts() + "<br/>");
    console.log("dtsb: " + date.dtsb() + "<br/>");
    console.log("code: " + date.code() + "<br/>");
    console.log("size: " + date.size() + "<br/>");
    console.log("raw: " + date.raw() + "<br/>");
    console.log("qb64: " + date.qb64() + "<br/>");
    console.log("qb64b: " + date.qb64b() + "<br/>");
    console.log("qb2: " + date.qb2() + "<br/>");
    }

main()
