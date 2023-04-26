# IDAPython_WDFFunctionRepair

基于IDAPython的WDF函数修复脚本

目前功能分两部分，一部分是，

1：如果发现函数是跳板函数，那么直接修改跳板函数的函数名，

2：如果发现函数不是跳板函数，而是直接的 imp 函数，那么就只能修改汇编了。


