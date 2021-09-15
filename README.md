# Sparkle Lite
A lightweight Sparkle update protocol implementation, it written with C++ and exposed a set of simple ANSI C interfaces so it could be integrated into any application.



### Features

+ Fully Sparkle2.0 specifications compatible

+ Cross platform (*Current Windows support only*)

+ Pure ANSI C interfaces

+ Simple to use & integrate

+ No UI integrated

  > Pros
  >
  > + Customize your own workflow and UI, so the user experience could be unified and harmonious
  >
  > Cons
  >
  > + A little bit extra work is required



### APIs

​	Update lifetime

> SETUP -> CUSTOMIZE -> CHECK -> DOWNLOAD -> INSTALL

+ **SETUP**

  ```c
  SPARKLE_API_DELC(SparkleError) sparkle_setup(
      const Callbacks* callbacks, 
      const char* appCurrentVer, 
      const char* appcastURL, 
      const char* pemPubKey, 
      const char* sslCA, 
      const char* preferLang, 
      const char** acceptChannels, 
      int acceptChannelCount
  )
  ```

+ **CUSTOMIZE**

  ```c
  SPARKLE_API_DELC(void) sparkle_customize_http_header(
      const char* key, 
      const char* value
  )
  ```

  

+ **CHECK**

  ```c
  SPARKLE_API_DELC(void) sparkle_customize_http_header(
      const char* key, 
      const char* value
  )
  ```

  

+ **DOWNLOAD**

  ```c
  SPARKLE_API_DELC(SparkleError) sparkle_download_to_file(
      const char* dstFile
  )
      
  SPARKLE_API_DELC(SparkleError) sparkle_download_to_buffer(
      void* buffer, 
      size_t* bufferSize
  )
  ```

  

+ **INSTALL**

  ```c
  SPARKLE_API_DELC(SparkleError) sparkle_install(
      const char* overrideArgs
  )
  ```

  

### Build

+ Dependencies, the following 3rd-party libraries are used to perform http(s) request and parse xml

  > openssl 1.1.1.
  >
  > cpp-httplib
  >
  > pugi-xml



### Extra Hints

+ File an issue if you encounter any bug

