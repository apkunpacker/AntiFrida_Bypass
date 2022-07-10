/*
Made By @ApkUnpacker on 29-6-2022 
Uploaded on 3-7-2022 ( so i can remember that i faced 4 days internet ban in my area and in free time made this. lol)
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
var ourlib = "libxyz.so";
var p_pthread_create = Module.findExportByName("libc.so", "pthread_create");
var pthread_create = new NativeFunction(p_pthread_create, "int", ["pointer", "pointer", "pointer", "pointer"]);
Interceptor.replace(p_pthread_create, new NativeCallback(function(ptr0, ptr1, ptr2, ptr3) {
    var ret = ptr(0);
    if (gmn(ptr0) == ourlib) {
        console.log("Thread Created ptr0 : ", gmn(ptr0), Mod, ptr0.sub(Mod));
    }
    if (gmn(ptr1) == ourlib) {
        var Mod = Module.findBaseAddress(ourlib)
        console.log("Thread Created ptr1 : ", gmn(ptr1), Mod, ptr1.sub(Mod));
        Interceptor.attach(Mod.add(ptr1.sub(Mod)), {
            onEnter: function(args) {
                console.log("New Thread Func", ptr1.sub(Mod), "arg : ", args[0], args[1]);
            },
            onLeave: function(retval) {
                console.log("New Thread Func Return : ", retval);
            }
        });
    }
    if (gmn(ptr2) == ourlib) {
        var Mod = Module.findBaseAddress(ourlib)
        console.log("Thread Created ptr2 : ", gmn(ptr2), Mod, ptr2.sub(Mod));
        Interceptor.attach(Mod.add(ptr2.sub(Mod)), {
            onEnter: function(args) {
                console.log("New Thread Func", ptr2.sub(Mod), "arg : ", args[0], args[1]);
            },
            onLeave: function(retval) {
                console.log("New Thread Func Return : ", retval);
            }
        });
    }
    if (gmn(ptr3) == ourlib) {
        var Mod = Module.findBaseAddress(ourlib)
        console.log("Thread Created ptr3 : ", gmn(ptr3), Mod, ptr3.sub(Mod));
        Interceptor.attach(Mod.add(ptr3.sub(Mod)), {
            onEnter: function(args) {
                console.log("New Thread Func", ptr3.sub(Mod), "arg : ", args[0], args[1]);
            },
            onLeave: function(retval) {
                console.log("New Thread Func Return : ", retval);
            }
        });
    }
    if (ptr1.isNull() && ptr3.isNull()) {
        console.warn("loading fake pthread_create");
        /* return -1 if you not want to create that thread */
        return pthread_create(ptr0, ptr1, ptr2, ptr3);
        // return -1;
    } else {       
        return pthread_create(ptr0, ptr1, ptr2, ptr3);;
    }
}, "int", ["pointer", "pointer", "pointer", "pointer"]));

function gmn(fnPtr) {
     if (fnPtr != null) {
        try {          
            return Process.getModuleByAddress(fnPtr).name;          
        } catch (e) {console.error(e);}            
    }
}
/* few method might check frida presence so added them */
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
var symlinkPtr = Module.findExportByName("libc.so", "symlink");
var symlink = new NativeFunction(symlinkPtr, 'int', ['pointer', 'pointer']);
Interceptor.replace(symlinkPtr, new NativeCallback(function(target, path) {
    var retval = symlink(target, path);
    console.log("symlink: ", target.readCString(), path.readCString());
    return retval;
}, 'int', ['pointer', 'pointer']))
var symlinkatPtr = Module.findExportByName("libc.so", "symlinkat");
var symlinkat = new NativeFunction(symlinkatPtr, 'int', ['pointer', 'int', 'pointer']);
Interceptor.replace(symlinkatPtr, new NativeCallback(function(target, fd, path) {
    var retval = symlinkat(target, fd, path);
    console.log("symlinkat : ", target.readCString(), path.readCString());
    return retval;
}, 'int', ['pointer', 'int', 'pointer']))
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
var sendPtr = Module.findExportByName("libc.so", "send");
var send2 = new NativeFunction(sendPtr, 'int', ['int', 'pointer', 'int', 'int']);
Interceptor.replace(sendPtr, new NativeCallback(function(socksfd, msg, slen, flag, daddr, dlen) {
    var retval = send2(socksfd, msg, slen, flag);
    console.log("send : ", socksfd, msg.readCString(), slen, flag);
    return retval;
}, 'int', ['int', 'pointer', 'int', 'int']))
var sendtoPtr = Module.findExportByName("libc.so", "sendto");
var sendto = new NativeFunction(sendtoPtr, 'int', ['int', 'pointer', 'int', 'int', 'pointer', 'int']);
Interceptor.replace(sendtoPtr, new NativeCallback(function(socksfd, msg, slen, flag, daddr, dlen) {
    var retval = sendto(socksfd, msg, slen, flag, daddr, dlen);
    //  console.log("sendto : ",socksfd,msg.readCString(),slen,flag,daddr,dlen);                                       
    return retval;
}, 'int', ['int', 'pointer', 'int', 'int', 'pointer', 'int']))

const openPtr = Module.getExportByName('libc.so', 'open');
const open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
var readPtr = Module.findExportByName("libc.so", "read");
var read = new NativeFunction(readPtr, 'int', ['int', 'pointer', "int"]);

//if process name not work correctly you can replace manually with your package name here 
var FakeMaps = "/data/data/" + ProName + "/maps";
var FOpenMaps = "/data/data/" + ProName + "/fmaps";
var FakeTask = "/data/data/" + ProName + "/task";
var FakeExE = "/data/data/" + ProName + "/exe";
var FakeMounts = "/data/data/" + ProName + "/mounts";
var FakeStatus = "/data/data/" + ProName + "/status";
var MapsFile = new File(FakeMaps, "w");
var TaskFile = new File(FakeTask, "w");
var ExEFile = new File(FakeExE, "w");
var FMapsFile = new File(FOpenMaps, "w");
var FMountFile = new File(FakeMounts, "w");
var StatusFile = new File(FakeStatus, "w");
var MapsBuffer = Memory.alloc(512);
var TaskBuffer = Memory.alloc(512);
var ExEBuffer = Memory.alloc(512);
var FopenBuffer = Memory.alloc(512);
var MountBuffer = Memory.alloc(512);
var StatusBuffer = Memory.alloc(512);
var Open64MapsBuffer = Memory.alloc(512);
Interceptor.replace(openPtr, new NativeCallback(function(pathname, flag) {
    var FD = open(pathname, flag);
    var ch = pathname.readCString();
    if (ch.indexOf("/proc/") >= 0 && ch.indexOf("maps") >= 0) {
          console.log("open : ", pathname.readCString()) 
        while (parseInt(read(FD, MapsBuffer, 512)) !== 0) {
            var MBuffer = MapsBuffer.readCString();
            MBuffer = MBuffer.replaceAll("/data/local/tmp/re.frida.server/frida-agent-64.so", "FakingMaps");
            MBuffer = MBuffer.replaceAll("re.frida.server", "FakingMaps");
            MBuffer = MBuffer.replaceAll("re.frida", "FakingMaps");
            MBuffer = MBuffer.replaceAll("re.", "FakingMaps");
            MBuffer = MBuffer.replaceAll("frida.", "FakingMaps");
            MBuffer = MBuffer.replaceAll("frida-agent-64.so", "FakingMaps");
            MBuffer = MBuffer.replaceAll("rida-agent-64.so", "FakingMaps");
            MBuffer = MBuffer.replaceAll("agent-64.so", "FakingMaps");
            MBuffer = MBuffer.replaceAll("frida-agent-32.so", "FakingMaps");
            MBuffer = MBuffer.replaceAll("frida-helper-32", "FakingMaps");
            MBuffer = MBuffer.replaceAll("frida-helper", "FakingMaps");
            MBuffer = MBuffer.replaceAll("frida-agent", "FakingMaps");
            MBuffer = MBuffer.replaceAll("pool-frida", "FakingMaps");
            MBuffer = MBuffer.replaceAll("frida", "FakingMaps");
            MBuffer = MBuffer.replaceAll("frida-", "FakingMaps");
            MBuffer = MBuffer.replaceAll("/data/local/tmp", "/data");
            MBuffer = MBuffer.replaceAll("server", "FakingMaps");
            MBuffer = MBuffer.replaceAll("frida-server", "FakingMaps");
            MBuffer = MBuffer.replaceAll("linjector", "FakingMaps");
            MBuffer = MBuffer.replaceAll("gum-js-loop", "FakingMaps");
            MBuffer = MBuffer.replaceAll("frida_agent_main", "FakingMaps");
            MBuffer = MBuffer.replaceAll("gmain", "FakingMaps");
            MBuffer = MBuffer.replaceAll("frida", "FakingMaps");
            MBuffer = MBuffer.replaceAll("magisk", "FakingMaps");
            MBuffer = MBuffer.replaceAll(".magisk", "FakingMaps");
            MBuffer = MBuffer.replaceAll("/sbin/.magisk", "FakingMaps");
            MBuffer = MBuffer.replaceAll("libriru", "FakingMaps");
            MBuffer = MBuffer.replaceAll("xposed", "FakingMaps");
            MapsFile.write(MBuffer);
            // console.log("MBuffer : ",MBuffer);                                     
        }
        var filename = Memory.allocUtf8String(FakeMaps);
        return open(filename, flag);
    }
    if (ch.indexOf("/proc") >= 0 && ch.indexOf("task") >= 0) {
        // console.log("open : ", pathname.readCString()) 
        while (parseInt(read(FD, TaskBuffer, 512)) !== 0) {
            var buffer = TaskBuffer.readCString();
            buffer = buffer.replaceAll("re.frida.server", "FakingTask");
            buffer = buffer.replaceAll("frida-agent-64.so", "FakingTask");
            buffer = buffer.replaceAll("rida-agent-64.so", "FakingTask");
            buffer = buffer.replaceAll("agent-64.so", "FakingTask");
            buffer = buffer.replaceAll("frida-agent-32.so", "FakingTask");
            buffer = buffer.replaceAll("frida-helper-32", "FakingTask");
            buffer = buffer.replaceAll("frida-helper", "FakingTask");
            buffer = buffer.replaceAll("frida-agent", "FakingTask");
            buffer = buffer.replaceAll("pool-frida", "FakingTask");
            buffer = buffer.replaceAll("frida", "FakingTask");
            buffer = buffer.replaceAll("/data/local/tmp", "/data");
            buffer = buffer.replaceAll("server", "FakingTask");
            buffer = buffer.replaceAll("frida-server", "FakingTask");
            buffer = buffer.replaceAll("linjector", "FakingTask");
            buffer = buffer.replaceAll("gum-js-loop", "FakingTask");
            buffer = buffer.replaceAll("frida_agent_main", "FakingTask");
            buffer = buffer.replaceAll("gmain", "FakingTask");
            buffer = buffer.replaceAll("magisk", "FakingTask");
            buffer = buffer.replaceAll(".magisk", "FakingTask");
            buffer = buffer.replaceAll("/sbin/.magisk", "FakingTask");
            buffer = buffer.replaceAll("libriru", "FakingTask");
            buffer = buffer.replaceAll("xposed", "FakingTask");
            buffer = buffer.replaceAll("pool-spawner", "FakingTask");
            buffer = buffer.replaceAll("gdbus", "FakingTask");            
            TaskFile.write(buffer);
            // console.log(buffer);
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
            // console.log("MNTBuffer : ",MNTBuffer);                                     
        }
        var mountname = Memory.allocUtf8String(FakeMounts);
        return open(mountname, flag);
    }
    /*
      if (ch.indexOf("/proc/") >=0 && ch.indexOf("status") >=0) {     
         console.log("open : ", pathname.readCString()) 
         while (parseInt(read(FD, StatusBuffer, 512)) !== 0) {
         var PStatus = StatusBuffer.readCString();   
         if (PStatus.indexOf("TracerPid:") > -1) {
                StatusBuffer.writeUtf8String("TracerPid:\t0");
                console.log("Bypassing TracerPID Check");               
            }
         StatusFile.write(PStatus);                                                
                }
            var statusname = Memory.allocUtf8String(FakeStatus);
            return open(statusname, flag);  
    }
     */
    if (ch.indexOf("/proc") >= 0 && ch.indexOf("exe") >= 0) {
        console.log("open : ", pathname.readCString())
        while (parseInt(read(FD, ExEBuffer, 512)) !== 0) {
            var buffer = ExEBuffer.readCString();
            //  console.warn(buffer)
            buffer = buffer.replaceAll("frida-agent-64.so", "StaySafeStayHappy");
            buffer = buffer.replaceAll("frida-agent-32.so", "StaySafeStayHappy");
            buffer = buffer.replaceAll("re.frida.server", "StaySafeStayHappy");
            buffer = buffer.replaceAll("frida-helper-32", "StaySafeStayHappy");
            buffer = buffer.replaceAll("frida-helper", "StaySafeStayHappy");
            buffer = buffer.replaceAll("pool-frida", "StaySafeStayHappy");
            buffer = buffer.replaceAll("frida", "StaySafeStayHappy");
            buffer = buffer.replaceAll("/data/local/tmp", "/data");
            buffer = buffer.replaceAll("frida-server", "StaySafeStayHappy");
            buffer = buffer.replaceAll("linjector", "StaySafeStayHappy");
            buffer = buffer.replaceAll("gum-js-loop", "StaySafeStayHappy");
            buffer = buffer.replaceAll("frida_agent_main", "StaySafeStayHappy");
            buffer = buffer.replaceAll("gmain", "StaySafeStayHappy");
            buffer = buffer.replaceAll("frida-agent", "StaySafeStayHappy");
            ExEFile.write(buffer);
        }
        var filename3 = Memory.allocUtf8String(FakeExE);
        return open(filename3, flag);
    }
    return FD;
}, 'int', ['pointer', 'int']))
var fgetsPtr = Module.findExportByName("libc.so", "fgets");
var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
Interceptor.replace(fgetsPtr, new NativeCallback(function(buf, size, fp) {
    //var retval = fgets(buf, size, fp);
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
    //  console.log(buf.readCString());
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
     
//    console.log("readlink : ", pathname.readCString(), buffer.readCString());
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
     
 //   console.log("readlinkat : ", pathname.readCString(), buffer.readCString());
   return retval;
}, 'int', ['int', 'pointer', 'pointer', 'int']))


Interceptor.attach(Module.findExportByName(null, "strstr"),{
    onEnter: function(args){
        this.frida = false;
        var str1 = args[0].readCString();
        var str2 = args[1].readCString();      
        if(str1.indexOf("frida")!==-1  || str2.indexOf("frida")!==-1 ||
          str1.indexOf("gum-js-loop")!==-1 || str2.indexOf("gum-js-loop")!==-1 ||
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


//Enabling it might give crash on some apps 
/*
Interceptor.attach(Module.findExportByName("libc.so", "read"), {
    onEnter: function(args) {
        try {
            var buffer = args[1].readCString();
            if (buffer.indexOf("frida") >= 0) {
                buffer = buffer.replaceAll("re.frida.server", "StaySafeStayHappy");
                buffer = buffer.replaceAll("frida-agent-64.so", "StaySafeStayHappy");
                buffer = buffer.replaceAll("rida-agent-64.so", "StaySafeStayHappy");
                buffer = buffer.replaceAll("agent-64.so", "StaySafeStayHappy");
                buffer = buffer.replaceAll("frida-agent-32.so", "StaySafeStayHappy");
                buffer = buffer.replaceAll("frida-helper-32", "StaySafeStayHappy");
                buffer = buffer.replaceAll("frida-helper", "StaySafeStayHappy");
                buffer = buffer.replaceAll("frida-agent", "StaySafeStayHappy");
                buffer = buffer.replaceAll("pool-frida", "StaySafeStayHappy");
                buffer = buffer.replaceAll("frida", "StaySafeStayHappy");
                buffer = buffer.replaceAll("/data/local/tmp", "/data");
                buffer = buffer.replaceAll("server", "StaySafeStayHappy");
                buffer = buffer.replaceAll("frida-server", "StaySafeStayHappy");
                buffer = buffer.replaceAll("linjector", "StaySafeStayHappy");
                buffer = buffer.replaceAll("gum-js-loop", "StaySafeStayHappy");
                buffer = buffer.replaceAll("frida_agent_main", "StaySafeStayHappy");
                buffer = buffer.replaceAll("gmain", "StaySafeStayHappy");
                buffer = buffer.replaceAll("magisk", "StaySafeStayHappy");
                buffer = buffer.replaceAll(".magisk", "StaySafeStayHappy");
                buffer = buffer.replaceAll("/sbin/.magisk", "StaySafeStayHappy");
                buffer = buffer.replaceAll("libriru", "StaySafeStayHappy");
                buffer = buffer.replaceAll("xposed", "StaySafeStayHappy");
                args[1].writeUtf8String(buffer);
            }
        } catch (e) {
            //console.error(e);
        }
    }
});
*/

/*
var memcpyPtr = Module.findExportByName("libc.so", "memcpy");
var memcpy = new NativeFunction(memcpyPtr, 'pointer', ['pointer', 'pointer', 'int']);
Interceptor.replace(memcpyPtr, new NativeCallback(function(dest, src, len) {
    var retval = memcpy(dest, src, len);
    if(dest.readCString() != null && src.readCString() != null && (dest.readCString().indexOf("frida")>=0 || src.readCString().indexOf("frida")>=0) )
    {
        //console.warn("memcpy : ",dest.readCString(),src.readCString());
        var buffer = dest.readCString();
        var buffer2 = src.readCString();
        buffer = buffer.replaceAll("re.frida.server","StaySafeStayHappy");                                                         
        buffer = buffer.replaceAll("frida-agent-64.so","StaySafeStayHappy");
        buffer = buffer.replaceAll("rida-agent-64.so","StaySafeStayHappy");
        buffer = buffer.replaceAll("agent-64.so","StaySafeStayHappy");        
        buffer = buffer.replaceAll("frida-agent-32.so","StaySafeStayHappy");       
        buffer = buffer.replaceAll("frida-helper-32","StaySafeStayHappy");        
        buffer = buffer.replaceAll("frida-helper","StaySafeStayHappy"); 
        buffer = buffer.replaceAll("frida-agent","StaySafeStayHappy");        
        buffer = buffer.replaceAll("pool-frida","StaySafeStayHappy");            
        buffer = buffer.replaceAll("frida","StaySafeStayHappy");
        buffer = buffer.replaceAll("/data/local/tmp","/data");
        buffer = buffer.replaceAll("server","StaySafeStayHappy");
        buffer = buffer.replaceAll("frida-server","StaySafeStayHappy");
        buffer = buffer.replaceAll("linjector","StaySafeStayHappy");
        buffer = buffer.replaceAll("gum-js-loop","StaySafeStayHappy");
        buffer = buffer.replaceAll("frida_agent_main","StaySafeStayHappy");
        buffer = buffer.replaceAll("gmain","StaySafeStayHappy");
        buffer2 = buffer2.replaceAll("re.frida.server","StaySafeStayHappy");                                                         
        buffer2 = buffer2.replaceAll("frida-agent-64.so","StaySafeStayHappy");
        buffer2 = buffer2.replaceAll("rida-agent-64.so","StaySafeStayHappy");
        buffer2 = buffer2.replaceAll("agent-64.so","StaySafeStayHappy");        
        buffer2 = buffer2.replaceAll("frida-agent-32.so","StaySafeStayHappy");       
        buffer2 = buffer2.replaceAll("frida-helper-32","StaySafeStayHappy");        
        buffer2 = buffer2.replaceAll("frida-helper","StaySafeStayHappy"); 
        buffer2 = buffer2.replaceAll("frida-agent","StaySafeStayHappy");        
        buffer2 = buffer2.replaceAll("pool-frida","StaySafeStayHappy");            
        buffer2 = buffer2.replaceAll("frida","StaySafeStayHappy");
        buffer2 = buffer2.replaceAll("/data/local/tmp","/data");
        buffer2 = buffer2.replaceAll("server","StaySafeStayHappy");
        buffer2 = buffer2.replaceAll("frida-server","StaySafeStayHappy");
        buffer2 = buffer2.replaceAll("linjector","StaySafeStayHappy");
        buffer2 = buffer2.replaceAll("gum-js-loop","StaySafeStayHappy");
        buffer2 = buffer2.replaceAll("frida_agent_main","StaySafeStayHappy");
        buffer2 = buffer2.replaceAll("gmain","StaySafeStayHappy");
        dest.writeUtf8String(buffer);
        src.writeUtf8String(buffer2);
       // console.log(buffer,buffer2);
        return memcpy(dest, src, len);
    }
    return retval;
}, 'pointer', ['pointer', 'pointer', 'int']))
*/
