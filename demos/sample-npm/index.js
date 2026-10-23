// 样例应用:真的 require 了 lodash,所以可达性会标成 reachable(已被引用)。
// minimist 没在源码里引用,会被标成 direct —— 用来展示两种可达性的区别。
const _ = require("lodash");

function buildUserProfile(input) {
  // _.merge 在旧版 lodash 存在原型链污染(CVE-2019-10744)
  const defaults = { role: "user", verified: false };
  return _.merge(defaults, input);
}

module.exports = { buildUserProfile };
