/*
Some app detect root/frida/lsposed/ etc but in callback shows "something is detected" by a dialog box instead of direct crashing
In this code we try to make those dialogbox cancelable so just touch outside those dialog box to remove them
and continue usual pentesting.
But remember if app have analytics/threatwatch telemetry, they still can see on server that application 
is being running in insecure environment.
*/
Java.performNow(function() {
    try {
        let AlertDialog = Java.use("android.app.AlertDialog");
        AlertDialog.show.implementation = function() {
            console.warn("Hooked AlertDialog.show()");
            //stacktrace()
            this.show();
            this.setCancelable(true);
            this.setCanceledOnTouchOutside(true);
        }
    } catch (error) {
        console.error("Error :", error);
    }
})

function stacktrace() {
    Java.perform(function() {
        let AndroidLog = Java.use("android.util.Log");
        let ExceptionClass = Java.use("java.lang.Exception");
        console.warn(AndroidLog.getStackTraceString(ExceptionClass.$new()));
    });
}


try {
    var p_pthread_create = Module.findExportByName("libc.so", "pthread_create");
    var pthread_create = new NativeFunction(p_pthread_create, "int", ["pointer", "pointer", "pointer", "pointer"]);
    Interceptor.replace(p_pthread_create, new NativeCallback(function(ptr0, ptr1, ptr2, ptr3) {
        if (ptr1.isNull() && ptr3.isNull()) {
            console.log("Possible thread creation for checking. Disabling it");
            return -1;
        } else {
            return pthread_create(ptr0, ptr1, ptr2, ptr3);
        }
    }, "int", ["pointer", "pointer", "pointer", "pointer"]));
} catch (error) {
    console.log("Error", error)
}
