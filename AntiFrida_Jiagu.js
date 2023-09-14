let Library = "libjiagu_64.so";
let Arm64Pattern = "00 03 3f d6 a0 06 00 a9";
let PackageName = ProcessName();

function ProcessName() {
  let openPtr = Module.getExportByName('libc.so', 'open');
  let open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
  let readPtr = Module.getExportByName('libc.so', 'read');
  let read = new NativeFunction(readPtr, 'int', ['int', 'pointer', 'int']);
  let closePtr = Module.getExportByName('libc.so', 'close');
  let close = new NativeFunction(closePtr, 'int', ['int']);
  let path = Memory.allocUtf8String('/proc/self/cmdline');
  let fd = open(path, 0);
  if (fd != -1) {
    let buffer = Memory.alloc(0x1000);
    let result = read(fd, buffer, 0x1000);
    close(fd);
    result = ptr(buffer).readCString();
    return result;
  }
  return -1;
}
Interceptor.attach(Module.getExportByName(null, "android_dlopen_ext"), {
  onEnter: function(args) {
    let AllLib = args[0].readCString();
    if (AllLib.indexOf(Library) != -1) {
      this.HookJiagu = true;
    }
  },
  onLeave: function(args) {
    if (this.HookJiagu) {
      let Jiagu = Process.findModuleByName(Library);
      Memory.scan(Jiagu.base, Jiagu.size, Arm64Pattern, {
        onMatch: function(found, sizes) {
          Interceptor.attach(found, function(args) {
            Memory.protect(this.context.x0, Process.pointerSize, 'rwx');
            try {
              let arg0 = this.context.x0.readCString()
              if (arg0 && (arg0.indexOf("/proc/") != -1 && arg0.indexOf("/maps") != -1)) {
                this.context.x0.writeUtf8String("/proc/self/cmdline")
              }
            } catch (e) {}
          })
        },
        onComplete: function(msg) {
          console.log("Frida Detection Bypassed");
        }
      })
    }
  }
})
