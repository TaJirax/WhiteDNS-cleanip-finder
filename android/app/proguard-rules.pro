# gomobile bindings: Go calls these through JNI by name.
-keep class go.** { *; }
-keep class com.whitescan.engine.** { *; }
# Kotlin implementations of Go callback interfaces (ScanListener) are invoked from Go.
-keep class * implements com.whitescan.engine.mobile.** { *; }
