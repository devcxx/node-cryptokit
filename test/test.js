const cryto = require("../lib/binding.js");
const path = require('path')

const assert = require("assert");
let jpg = path.join(__dirname,  '../ctk.jpg')

cryto.init(jpg)
let iv =cryto.createI()

console.log(iv)