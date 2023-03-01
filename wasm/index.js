// Note that a dynamic `import` statement here is required due to
// webpack/webpack#6615, but in theory `import { greet } from './pkg';`
// will work here one day as well!
const rust = import('./pkg');

rust
  .then(m => {
    date = new m.Dater(dts = "2020-08-22T17:50:09.988921+00:00");
    alert("Date: \ndts: " + date.dts() +
      "\ndtsb: " + date.dtsb() +
      "\ncode: " + date.code() +
      "\nsize: " + date.size() +
      "\nraw: " + date.raw() +
      "\nqb64: " + date.qb64() +
      "\nqb64b: " + date.qb64b() +
      "\nqb2: " + date.qb2()

    );
  })
  .catch(console.error);
