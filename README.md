# Sparkle Lite
A lightweight Sparkle update specification implementation, it is written in C++ and exposed a set of simple ANSI C interfaces so it could be integrated into any application.



### What's Sparkle

[Sparkle](https://sparkle-project.org/) is an open source specification (and an official implementation for MacOS), which provides a modern, secure, and flexible update workflow for any application.

Anyway, if your app needs the update, **Sparkle is just for you**



### Features

+ Sparkle 2.0 specifications compatible

+ Dual **DSA** & **EdDSA(Ed25519)** signature algorithms support

+ Cross platform (*Currently Windows support only*)

+ Pure ANSI C interfaces

+ Easy to use & integrate

+ No bloated UI integration

  > Why
  >
  > + Every app has its own style, it's hard to design/implement an update window to fit them all
  >
  > Pros
  >
  > + Customize your own workflow and UI, so the user experience could be unified and harmonious
  >
  > Cons
  >
  > + A little bit extra work is required


### How to use

+ Just include `sparkel_api.h` and you are ready to go
  > of course, you need to make sure all files in the `impl` subfolder will be compiled together.

### APIs

​	Update lifetime

> SETUP -> CUSTOMIZE -> CHECK -> DOWNLOAD -> INSTALL

+ **SETUP**

  ```c
  enum SignAlgo
  {
      kNoSign,
      kDSA,
      kEd25519
  };
  
  SPARKLE_API_DELC(SparkleError) sparkle_setup(
      const SparkleCallbacks* callbacks, 
      const char* appCurrentVer, 
      const char* appcastURL, 
      SignAlgo signVerifyAlgo,
      const char* signVerifyPubKey, 
      const char* sslCA);
  ```
  
  
  
+ **CUSTOMIZE**

  ```c
  SPARKLE_API_DELC(void) sparkle_customize_http_header(
      const char* key, 
      const char* value);
  ```
  
  
  
+ **CHECK**

  ```c
  SPARKLE_API_DELC(SparkleError) sparkle_check_update(
  		const char* preferLang,
  		const char** acceptChannels,
  		int acceptChannelCount,
  		void* userdata);
  ```
  
  
  
+ **DOWNLOAD**

  ```c
  SPARKLE_API_DELC(SparkleError) sparkle_download_to_file(
      const char* dstFile, 
      void* userdata);
      
  SPARKLE_API_DELC(SparkleError) sparkle_download_to_buffer(
      void* buffer, 
      size_t* bufferSize, 
      void* userdata);
  ```

  

+ **INSTALL**

  ```c
  SPARKLE_API_DELC(SparkleError) sparkle_install(
      const char* overrideArgs, 
      void* userdata);
  ```


### Build

+ Dependencies, the following 3rd-party libraries are used to perform http(s) request and parse xml

  > openssl 1.1.1
  >
  > pugi-xml



### Extra Hints

+ File an issue if you encounter any bug

