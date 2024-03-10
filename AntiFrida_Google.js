/*
Created By @apkunpacker
It only bypass anti-frida detection which crash app even after frida-server is closed.
It won't work if you use it with any java hook ( Java.use("xyz") )
Java.use have seperate detections.
I hate those guys who sell open source scripts.
*/
Interceptor.attach(Module.findExportByName(null, "strlen"), {
    onEnter: function(args) {
        var cmd = args[0].readCString();
        if (cmd.indexOf("rwxp") !== -1) {          
            cmd = cmd.replaceAll("rwxp", "r-xp");
            args[0].writeUtf8String(cmd);
        }
    }
})
