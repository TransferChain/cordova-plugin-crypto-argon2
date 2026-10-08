// Based on lambdapioneer/argon2kt 1.6.0, Copyright Daniel Hugenroth, MIT.
// Output buffers are JVM-owned; no malloc allocation escapes through JNI.
#include <argon2.h>
#include <jni.h>
#include <cstring>

// JVM-owned direct buffers avoid escaping unmanaged malloc allocations.
// Java finally wipes them; reclamation follows the JVM allocation lifecycle.
static jobject allocate(JNIEnv *env, jint size) {
    jclass type = env->FindClass("java/nio/ByteBuffer");

    if (!type) return nullptr;

    jmethodID method = env->GetStaticMethodID(type, "allocateDirect", "(I)Ljava/nio/ByteBuffer;");
    jobject result = method ? env->CallStaticObjectMethod(type, method, size) : nullptr;

    env->DeleteLocalRef(type);
    return result;
}

// Do not let the compiler remove error-path output wiping.
// This helper only clears output memory owned by the current JNI call.
static void clear(void *memory, size_t length) {
    volatile unsigned char *bytes = static_cast<volatile unsigned char *>(memory);
    while (length--) *bytes++ = 0;
}

extern "C" JNIEXPORT jint JNICALL Java_com_lambdapioneer_argon2kt_Argon2Jni_nativeArgon2Hash(
    JNIEnv *env, jobject, jint mode, jint version, jint time, jint memory, jint parallelism,
    jobject password, jobject salt, jint length, jobject hashTarget, jobject encodedTarget) {
    // JNI INPUT CONTRACT
    // The Java adapter supplies direct buffers whose capacities equal the encoded
    // input sizes. GetDirectBufferAddress borrows their backing storage for this
    // synchronous call; no input pointer is saved after returning to Java.
    // A negative capacity indicates an unsupported buffer. An empty password is
    // valid even when its address is null, but salt must have storage and meet bounds.
    //
    // The bounds below defend the C boundary independently of the JS/Java adapters.
    // Keep the JNI symbol/signature aligned with the pinned argon2kt Java classes;
    // changing a native parameter order can corrupt calls before validation runs.
    const jlong passwordLength = env->GetDirectBufferCapacity(password);
    const jlong saltLength = env->GetDirectBufferCapacity(salt);

    const void *passwordBytes = env->GetDirectBufferAddress(password);
    const void *saltBytes = env->GetDirectBufferAddress(salt);
    if (passwordLength < 0 || (passwordLength && !passwordBytes)) return 1001;

    if (saltLength < 0 || !saltBytes) return 1002;

    if (length < 4 || length > 1024 || saltLength < 8 || saltLength > 1024 ||
        passwordLength > 4096 || mode < 0 || mode > 2 || version != 0x13 ||
        time < 1 || time > 10 || parallelism < 1 || parallelism > 4 ||
        memory < 8 * parallelism || memory > 65536) return ARGON2_INCORRECT_PARAMETER;

    // Validate bounds before allocation and C calculation. When changing limits,
    // update Java/Swift/JS validation and the corresponding vectors together.
    // JNI/C INTEGER BOUNDARY
    // jint matches Java int for bounded costs. Buffer capacity arrives as jlong:
    // check its sign and range before converting to C lengths. size_t is used for
    // allocation/string sizes expected by the C API. Bounds make later narrowing
    // conversions safe; a cast by itself is not validation.
    // Check lane-dependent memory minimum and output limits before calculating
    // encoded size or allocating buffers, so invalid input cannot drive allocations.
    const size_t encodedLength = argon2_encodedlen(time, memory, parallelism,
        static_cast<uint32_t>(saltLength), length, static_cast<argon2_type>(mode));

    if (encodedLength > 8192) return ARGON2_INCORRECT_PARAMETER;

    // Allocate outputs under JVM ownership before starting the expensive operation.
    // If allocation raises a Java exception, return immediately with it pending;
    // calling further JNI allocation APIs would obscure the original failure.
    jobject hash = allocate(env, length);

    if (!hash || env->ExceptionCheck()) return ARGON2_MEMORY_ALLOCATION_ERROR;

    jobject encoded = allocate(env, static_cast<jint>(encodedLength));

    if (!encoded || env->ExceptionCheck()) {
        env->DeleteLocalRef(hash);
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    void *output = env->GetDirectBufferAddress(hash);
    char *text = static_cast<char *>(env->GetDirectBufferAddress(encoded));
    // NESTED PARALLELISM AND JNI THREAD AFFINITY
    // This call owns its input references and outputs. argon2_hash constructs a local
    // context and runs lane workers internally; they are separate from Cordova workers
    // running independent derivations. The C call joins its internal work before
    // returning, keeping borrowed input storage valid through the calculation.
    // No JNIEnv or Java local reference is passed to those lane threads. JNIEnv is
    // thread-local; never cache it for another Cordova worker to use.
    // The application job limit is not the total internal Argon2 thread count.
    int status = argon2_hash(time, memory, parallelism, passwordBytes, passwordLength,
        saltBytes, saltLength, output, length, text, encodedLength,
        static_cast<argon2_type>(mode), version);

    // RESULT PUBLICATION
    // The C function has finished before buffers are attached to ByteBufferTarget.
    // Both target objects use the same pinned argon2kt wrapper class, whose byteBuffer
    // field is the handoff point into Kotlin. A successful handoff keeps the Java
    // objects reachable after these JNI local references are deleted.
    //
    // On field lookup/publication failure, mark the call failed and wipe output below.
    // Do not cache a local jclass between invocations: each native call may arrive on
    // a different Cordova worker thread.
    if (status == ARGON2_OK) {
        // Local JNI references belong to this call/thread. Never cache a local
        // class reference in a static variable; release it before returning.
        jclass type = env->GetObjectClass(hashTarget);
        jfieldID field = type ? env->GetFieldID(type, "byteBuffer", "Ljava/nio/ByteBuffer;") : nullptr;

        if (field && !env->ExceptionCheck()) {
            env->SetObjectField(hashTarget, field, hash);
            env->SetObjectField(encodedTarget, field, encoded);
        }

        if (type) env->DeleteLocalRef(type);
        if (!field || env->ExceptionCheck()) status = ARGON2_INCORRECT_PARAMETER;
    }

    // A failed C call may have partially written output. Wipe both buffers before
    // releasing local references; reference release alone does not overwrite bytes.
    if (status != ARGON2_OK) {
        clear(output, length);
        clear(text, encodedLength);
    }

    env->DeleteLocalRef(hash);
    env->DeleteLocalRef(encoded);
    return status;
}

extern "C" JNIEXPORT jint JNICALL Java_com_lambdapioneer_argon2kt_Argon2Jni_nativeArgon2Verify(
    JNIEnv *env, jobject, jint mode, jobject encoded, jobject password) {
    const jlong size = env->GetDirectBufferCapacity(encoded);
    const jlong passwordLength = env->GetDirectBufferCapacity(password);

    const char *text = static_cast<const char *>(env->GetDirectBufferAddress(encoded));
    const void *bytes = env->GetDirectBufferAddress(password);
    if (size < 1 || size > 8192 || !text || !std::memchr(text, 0, size) ||
        passwordLength < 0 || passwordLength > 4096 || (passwordLength && !bytes) ||
        mode < 0 || mode > 2) return ARGON2_INCORRECT_PARAMETER;

    return argon2_verify(text, bytes, passwordLength, static_cast<argon2_type>(mode));
}
