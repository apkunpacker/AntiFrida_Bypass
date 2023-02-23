/*
Made By @ApkUnpacker on 29-6-2022 
Uploaded on 3-7-2022 ( so i can remember that i faced 4 days internet ban in my area and in free time made this. lol)
Less of chance of crash compare to 1st script
*/
var ProName = ProcessName();

function ProcessName() {
    var openPtr = Module.getExportByName('libc.so', 'open');
    var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
    var readPtr = Module.getExportByName('libc.so', 'read');
    var read = new NativeFunction(readPtr, 'int', ['int', 'pointer', 'int']);
    var closePtr = Module.getExportByName('libc.so', 'close');
    var close = new NativeFunction(closePtr, 'int', ['int']);
    var path = Memory.allocUtf8String('/proc/self/cmdline');
    var fd = open(path, 0);
    if (fd != -1) {
        var buffer = Memory.alloc(0x1000);
        var result = read(fd, buffer, 0x1000);
        close(fd);
        result = ptr(buffer).readCString();
        return result;
    }
    return -1;
}

function gmn(fnPtr) {
        try {
            return Process.getModuleByAddress(fnPtr).name;
        } catch (e) {
            console.error(e);
        }
}
var inet_atonPtr = Module.findExportByName("libc.so", "inet_aton");
var inet_aton = new NativeFunction(inet_atonPtr, 'int', ['pointer', 'pointer']);
Interceptor.replace(inet_atonPtr, new NativeCallback(function(addrs, structure) {
    var retval = inet_aton(addrs, structure);
    console.log("inet_aton : ", addrs.readCString())
    return retval;
}, 'int', ['pointer', 'pointer']))
var popenPtr = Module.findExportByName("libc.so", "popen");
var popen = new NativeFunction(popenPtr, 'pointer', ['pointer', 'pointer']);
Interceptor.replace(popenPtr, new NativeCallback(function(path, type) {
    var retval = popen(path, type);
    console.log("popen : ", path.readCString());
    return retval;
}, 'pointer', ['pointer', 'pointer']))
var inet_addrPtr = Module.findExportByName("libc.so", "inet_addr");
var inet_addr = new NativeFunction(inet_addrPtr, 'int', ['int']);
Interceptor.replace(inet_addrPtr, new NativeCallback(function(path) {
    var retval = inet_addr(path);
    console.log("inet_addr : ", path.readCString())
    return retval;
}, 'int', ['int']))
var socketPtr = Module.findExportByName("libc.so", "socket");
var socket = new NativeFunction(socketPtr, 'int', ['int', 'int', 'int']);
Interceptor.replace(socketPtr, new NativeCallback(function(domain, type, proto) {
    var retval = socket(domain, type, proto);
    console.warn("socket  : ", domain, type, proto, "Return : ", retval)
    return retval;
}, 'int', ['int', 'int', 'int']))
var connectPtr = Module.findExportByName("libc.so", "connect");
var connect = new NativeFunction(connectPtr, 'int', ['int', 'pointer', 'int']);
Interceptor.replace(connectPtr, new NativeCallback(function(fd, addr, len) {
    var retval = connect(fd, addr, len);
    var family = addr.readU16();
    var port = addr.add(2).readU16();
    //port = ((port & 0xff) << 8) | (port >> 8);
    console.warn("Connect : ", family, "Port : ", port, "Return : ", retval);
    return retval;
}, 'int', ['int', 'pointer', 'int']))
//Make it true if you want to change maps, high chance of crash
var HookMaps = false;
const openPtr = Module.getExportByName('libc.so', 'open');
const open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
var readPtr = Module.findExportByName("libc.so", "read");
var read = new NativeFunction(readPtr, 'int', ['int', 'pointer', "int"]);
//if process name not work correctly you can replace manually with your package name here 
var FakeMaps = "/data/data/" + ProName + "/maps";
var FakeTask = "/data/data/" + ProName + "/task";
var FakeMounts = "/data/data/" + ProName + "/mounts";
var FakeStatus = "/data/data/" + ProName + "/status";
var MapsFile = new File(FakeMaps, "w");
var TaskFile = new File(FakeTask, "w");
var FMountFile = new File(FakeMounts, "w");
var StatusFile = new File(FakeStatus, "w");
var MapsBuffer = Memory.alloc(512);
var TaskBuffer = Memory.alloc(512);
var MountBuffer = Memory.alloc(512);
var StatusBuffer = Memory.alloc(512);
Interceptor.replace(openPtr, new NativeCallback(function(pathname, flag) {
    var FD = open(pathname, flag);
    var ch = pathname.readCString();
    if (HookMaps) {
        if (ch.indexOf("/proc/") >= 0 && ch.indexOf("maps") >= 0) {
            console.log("open : ", pathname.readCString())
            while (parseInt(read(FD, MapsBuffer, 512)) !== 0) {
                var MBuffer = MapsBuffer.readCString();
                MBuffer = MBuffer.replaceAll("/data/local/tmp/re.frida.server/frida-agent-64.so", "FakingMaps");
                MBuffer = MBuffer.replaceAll("re.frida.server", "FakingMaps");
                MBuffer = MBuffer.replaceAll("frida-agent-64.so", "FakingMaps");
                MBuffer = MBuffer.replaceAll("frida-agent-32.so", "FakingMaps");
                MBuffer = MBuffer.replaceAll("frida", "FakingMaps");
                MBuffer = MBuffer.replaceAll("/data/local/tmp", "/data");
                MapsFile.write(MBuffer);
            }
            var filename = Memory.allocUtf8String(FakeMaps);
            return open(filename, flag);
        }
    }
    if (ch.indexOf("/proc") >= 0 && ch.indexOf("task") >= 0) {
        while (parseInt(read(FD, TaskBuffer, 512)) !== 0) {
            var buffer = TaskBuffer.readCString();
            buffer = buffer.replaceAll("pool-frida", "FakingTask");
            buffer = buffer.replaceAll("frida", "FakingTask");
            buffer = buffer.replaceAll("/data/local/tmp", "/data");
            buffer = buffer.replaceAll("frida-server", "FakingTask");
            buffer = buffer.replaceAll("linjector", "FakingTask");
            buffer = buffer.replaceAll("gum-js-loop", "FakingTask");
            buffer = buffer.replaceAll("frida_agent_main", "FakingTask");
            buffer = buffer.replaceAll("gmain", "FakingTask");
            buffer = buffer.replaceAll("pool-spawner", "FakingTask");
            buffer = buffer.replaceAll("gdbus", "FakingTask");
            TaskFile.write(buffer);
        }
        var filename2 = Memory.allocUtf8String(FakeTask);
        return open(filename2, flag);
    }
    if (ch.indexOf("/proc/") >= 0 && ch.indexOf("mounts") >= 0) {
        console.log("open : ", pathname.readCString())
        while (parseInt(read(FD, MountBuffer, 512)) !== 0) {
            var MNTBuffer = MountBuffer.readCString();
            MNTBuffer = MNTBuffer.replaceAll("magisk", "StaySafeStayHappy");
            MNTBuffer = MNTBuffer.replaceAll("/sbin/.magisk", "StaySafeStayHappy");
            MNTBuffer = MNTBuffer.replaceAll("libriru", "StaySafeStayHappy");
            MNTBuffer = MNTBuffer.replaceAll("xposed", "StaySafeStayHappy");
            MNTBuffer = MNTBuffer.replaceAll("mirror", "StaySafeStayHappy");
            MNTBuffer = MNTBuffer.replaceAll("system_root", "StaySafeStayHappy");
            MNTBuffer = MNTBuffer.replaceAll("xposed", "StaySafeStayHappy")
            FMountFile.write(MNTBuffer);
        }
        var mountname = Memory.allocUtf8String(FakeMounts);
        return open(mountname, flag);
    }
    return FD;
}, 'int', ['pointer', 'int']))
var fgetsPtr = Module.findExportByName("libc.so", "fgets");
var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
Interceptor.replace(fgetsPtr, new NativeCallback(function(buf, size, fp) {
    var buffer = buf.readCString();
    buffer = buffer.replaceAll("re.frida.server", "FakingGets");
    buffer = buffer.replaceAll("frida-agent-64.so", "FakingGets");
    buffer = buffer.replaceAll("rida-agent-64.so", "FakingGets");
    buffer = buffer.replaceAll("agent-64.so", "FakingGets");
    buffer = buffer.replaceAll("frida-agent-32.so", "FakingGets");
    buffer = buffer.replaceAll("frida-helper-32", "FakingGets");
    buffer = buffer.replaceAll("frida-helper", "FakingGets");
    buffer = buffer.replaceAll("frida-agent", "FakingGets");
    buffer = buffer.replaceAll("pool-frida", "FakingGets");
    buffer = buffer.replaceAll("frida", "FakingGets");
    buffer = buffer.replaceAll("/data/local/tmp", "/data");
    buffer = buffer.replaceAll("server", "FakingGets");
    buffer = buffer.replaceAll("frida-server", "FakingGets");
    buffer = buffer.replaceAll("linjector", "FakingGets");
    buffer = buffer.replaceAll("gum-js-loop", "FakingGets");
    buffer = buffer.replaceAll("frida_agent_main", "FakingGets");
    buffer = buffer.replaceAll("gmain", "FakingGets");
    buffer = buffer.replaceAll("magisk", "FakingGets");
    buffer = buffer.replaceAll(".magisk", "FakingGets");
    buffer = buffer.replaceAll("/sbin/.magisk", "FakingGets");
    buffer = buffer.replaceAll("libriru", "FakingGets");
    buffer = buffer.replaceAll("xposed", "FakingGets");
    buf.writeUtf8String(buffer);
    return fgets(buf, size, fp);
}, 'pointer', ['pointer', 'int', 'pointer']))
var readlinkPtr = Module.findExportByName("libc.so", "readlink");
var readlink = new NativeFunction(readlinkPtr, 'int', ['pointer', 'pointer', 'int']);
Interceptor.replace(readlinkPtr, new NativeCallback(function(pathname, buffer, bufsize) {
    var retval = readlink(pathname, buffer, bufsize);
     if(buffer.readCString().indexOf("frida")!==-1 ||
            buffer.readCString().indexOf("gum-js-loop")!==-1||
            buffer.readCString().indexOf("gmain")!==-1 ||
            buffer.readCString().indexOf("linjector")!==-1 || 
            buffer.readCString().indexOf("/data/local/tmp")!==-1 || 
            buffer.readCString().indexOf("pool-frida")!==-1 || 
            buffer.readCString().indexOf("frida_agent_main")!==-1 ||
            buffer.readCString().indexOf("re.frida.server")!==-1 || 
            buffer.readCString().indexOf("frida-agent")!==-1 ||
            buffer.readCString().indexOf("frida-agent-64.so")!==-1 ||
            buffer.readCString().indexOf("frida-agent-32.so")!==-1 ||
            buffer.readCString().indexOf("frida-helper-32.so")!==-1 ||
            buffer.readCString().indexOf("frida-helper-64.so")!==-1                        
            ){
            console.log(buffer.readCString(), "Check in readlink");
            buffer.writeUtf8String("/system/framework/services.jar");            
            return readlink(pathname, buffer, bufsize);  
     }
    return retval;   
}, 'int', ['pointer', 'pointer', 'int']))
var readlinkatPtr = Module.findExportByName("libc.so", "readlinkat");
var readlinkat = new NativeFunction(readlinkatPtr, 'int', ['int', 'pointer', 'pointer', 'int']);
Interceptor.replace(readlinkatPtr, new NativeCallback(function(dirfd, pathname, buffer, bufsize) {
    var retval = readlinkat(dirfd, pathname, buffer, bufsize);
     if(buffer.readCString().indexOf("frida")!==-1 ||
            buffer.readCString().indexOf("gum-js-loop")!==-1||
            buffer.readCString().indexOf("gmain")!==-1 ||
            buffer.readCString().indexOf("linjector")!==-1 || 
            buffer.readCString().indexOf("/data/local/tmp")!==-1 || 
            buffer.readCString().indexOf("pool-frida")!==-1 || 
            buffer.readCString().indexOf("frida_agent_main")!==-1 ||
            buffer.readCString().indexOf("re.frida.server")!==-1 || 
            buffer.readCString().indexOf("frida-agent")!==-1 ||
            buffer.readCString().indexOf("frida-agent-64.so")!==-1 ||
            buffer.readCString().indexOf("frida-agent-32.so")!==-1 ||
            buffer.readCString().indexOf("frida-helper-32.so")!==-1 ||
            buffer.readCString().indexOf("frida-helper-64.so")!==-1                              
            ){
            console.log(buffer.readCString(), "Check in readlinkat");
            buffer.writeUtf8String("/system/framework/services.jar");           
            return readlinkat(dirfd, pathname, buffer, bufsize);
     }
   return retval;
}, 'int', ['int', 'pointer', 'pointer', 'int']))
Interceptor.attach(Module.findExportByName(null, "strstr"),{
    onEnter: function(args){
        this.frida = false;
        var str1 = args[0].readCString();
        var str2 = args[1].readCString();      
        if(str1.indexOf("frida")!==-1  || str2.indexOf("frida")!==-1 ||
          str1.indexOf("gum-js-loop")!==-1 || str2.indexOf("gum-js-loop")!==-1 ||
          str1.indexOf("gmain")!==-1 || str2.indexOf("gmain")!==-1 ||
          str1.indexOf("linjector")!==-1  || str2.indexOf("linjector")!==-1 ||
          str1.indexOf("/data/local/tmp")!==-1  || str2.indexOf("/data/local/tmp")!==-1 ||
          str1.indexOf("pool-frida")!==-1  || str2.indexOf("pool-frida")!==-1 ||
          str1.indexOf("frida_agent_main")!==-1  || str2.indexOf("frida_agent_main")!==-1 ||
          str1.indexOf("re.frida.server")!==-1  || str2.indexOf("re.frida.server")!==-1 ||
          str1.indexOf("frida-agent")!==-1  || str2.indexOf("frida-agent")!==-1 ||
          str1.indexOf("pool-spawner")!==-1  || str2.indexOf("pool-spawner")!==-1 ||
          str1.indexOf("frida-agent-64.so")!==-1  || str2.indexOf("frida-agent-64.so")!==-1 ||
          str1.indexOf("frida-agent-32.so")!==-1  || str2.indexOf("frida-agent-32.so")!==-1 ||
          str1.indexOf("frida-helper-32.so")!==-1  || str2.indexOf("frida-helper-32.so")!==-1 ||
          str1.indexOf("frida-helper-64.so")!==-1  || str2.indexOf("frida-helper-64.so")!==-1  ||
          str1.indexOf("/sbin/.magisk")!==-1  || str2.indexOf("/sbin/.magisk")!==-1  ||
          str1.indexOf("libriru")!==-1  || str2.indexOf("libriru")!==-1  ||
          str1.indexOf("magisk")!==-1  || str2.indexOf("magisk")!==-1                                
          ){          
            this.frida = true;
            console.log("strstr : ",str1,str2);
        }
    },
    onLeave: function(retval){
        if (this.frida) {
            retval.replace(ptr("0x0"));
        }
    }
});
