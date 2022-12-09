/* Description: Backtrace
 * Mode: S
 * Version: 1.0
 * Credit: github.com/iddoeldor/frida-snippets & https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @iddoeldor
 */
var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
console.warn("\n[-] ======== Backtrace Start  ========");
console.log(backtrace);
console.warn("\n[-] ======== Backtrace End  ========");
