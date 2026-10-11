/* 目录入口：让 `node --test p2pchat/tests/client`（以目录为参数）在任何 Node 上都能跑。
   Node 26 会把目录参数展开成同目录的 *.test.cjs，并因文件名不符合测试命名约定而忽略本文件；
   Node 24 不再展开目录参数，会把目录本身当成一个模块加载，于是落到这里，再按名字顺序逐个加载测试文件。
   本文件不含任何断言，也不改变任何测试的行为。 */
'use strict';
const fs=require('node:fs'),path=require('node:path');
for(const name of fs.readdirSync(__dirname).filter(n=>/\.test\.cjs$/.test(n)).sort())require(path.join(__dirname,name));
