/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */


#include <jni.h>
#include <cinttypes>
#include <android/log.h>
#include <gperf.h>
#include <openssl/ssl.h>
#include <curl/curl.h>


#define LOGI(...) \
  ((void)__android_log_print(ANDROID_LOG_INFO, "hell-libs::", __VA_ARGS__))

struct Buffer {
    char *start;
    char *pos;
    char *end;
    size_t size;
};

static int get_ssl_info(SSL *ssl, char *buffer, size_t len) {
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    size_t n = 0;

    n += snprintf(buffer, len, "Version: %s\n", SSL_get_version(ssl));
    len -= n;
    if (n < len)
        n += snprintf(buffer + n, len - n, "Resumed session: %s\n", SSL_session_reused(ssl) ? "yes" : "no");

    if (n < len)
        n += snprintf(buffer + n, len - n, "Cipher: %s\n", SSL_CIPHER_get_name(cipher));

    return n;
}

static size_t header_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t len = size * nmemb;
    return len;
}

static size_t write_body_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t len = size * nmemb;
    struct Buffer *resp = (struct Buffer *)userdata;

    size_t remain = resp->end - resp->pos;

    if (remain < len)
        len = remain;

    memcpy(resp->pos, ptr, len);
    resp->pos += len;
    return len;
}
static int ssl_new_session_cb(SSL *ssl, SSL_SESSION *sess) {
    struct Buffer *buffer = (struct Buffer *)SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
    buffer->pos += get_ssl_info(ssl, buffer->pos, buffer->end - buffer->pos);
    return 0;
}

static CURLcode ssl_ctx_callback(CURL *curl, void *ssl_ctx, void *userptr) {
    SSL_CTX *ctx = (SSL_CTX *)ssl_ctx;

    SSL_CTX_sess_set_new_cb(ctx, ssl_new_session_cb);
    SSL_CTX_set_app_data(ctx, userptr);
    return CURLE_OK;
}


static int get_time_stat(CURL *curl, char *buffer, size_t len) {
    double conn_time = 0;
    double handshake_time = 0;
    double firstbyte_time = 0;
    double total_time = 0;
    int n;

    curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME, &conn_time);
    curl_easy_getinfo(curl, CURLINFO_APPCONNECT_TIME, &handshake_time);
    curl_easy_getinfo(curl, CURLINFO_STARTTRANSFER_TIME, &firstbyte_time);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);

    n = snprintf(buffer, len, "Connect time:%f\n", conn_time);
    if (n < len)
        n += snprintf(buffer + n, len - n, "Handshake time:%f\n", handshake_time);
    if (n < len)
        n += snprintf(buffer + n, len - n, "Firstbyte time:%f\n", firstbyte_time);
    if (n < len)
        n += snprintf(buffer + n, len - n, "Total time:%f\n", total_time);

    return n;
}

static int curl_https_test(const char *url, struct Buffer *resp, int ssl_version) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if(curl) {
        CURLcode res;
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
        curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, ssl_ctx_callback);
        curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, (void *)resp);
        curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
        /* Default is TLSv1.3 if server support */
        if (ssl_version > 0)
            curl_easy_setopt(curl, CURLOPT_SSLVERSION, ssl_version);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)resp);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)resp);


        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            resp->pos += get_time_stat(curl, resp->pos, resp->end - resp->pos);
        } else {
            const char* strerr;
            strerr = curl_easy_strerror(res);
            size_t len = resp->end - resp->pos;
            if (len > strlen(strerr))
                len = strlen(strerr);
            strncpy(resp->pos, strerr, len);
            resp->pos += len;
        }


        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return 0;
}


/* This is a trivial JNI example where we use a native method
 * to return a new VM String. See the corresponding Java source
 * file located at:
 *
 *   app/src/main/java/com/example/hellolibs/MainActivity.java
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_hellolibs_MainActivity_stringFromJNI(JNIEnv *env, jobject thiz) {
    // Just for simplicity, we do this right away; correct way would do it in
    // another thread...
    //auto ticks = GetTicks();
    char buffer[4096] = {0};
    size_t size = sizeof(buffer) - 1;
    struct Buffer resp = {
            .start = buffer,
            .pos = buffer,
            .end = buffer + size,
            .size = size,
    };

    const char *head = "==========TLSv1.2==========\n";
    strncpy(resp.pos, head, strlen(head));
    resp.pos += strlen(head);

    curl_https_test("https://112.25.246.96/", &resp, CURL_SSLVERSION_TLSv1_2);

    head = "\n==========TLSv1.3==========\n";
    strncpy(resp.pos, head, strlen(head));
    resp.pos += strlen(head);
    /* Default is TLSv1.3 */
    curl_https_test("https://112.25.246.96/", &resp, CURL_SSLVERSION_MAX_DEFAULT);

    //ticks = GetTicks() - ticks;
    //LOGI("calculation time: %" PRIu64, ticks);
    return env->NewStringUTF(resp.start);
}