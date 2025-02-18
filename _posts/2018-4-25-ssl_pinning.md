---
title: 'Bypass SSL Pinning on iOS'
date: 2018-04-25
permalink: /posts/ssl_pinning/
tags:
  - cool posts
  - mobile
---

# Bypass SSL Pinning on iOS
## 0x0 Background
By default, HTTPS only ensures that the communication between two parties is not intercepted by a third party after the key exchange is completed. If an attacker launches a man-in-the-middle attack, they can still establish a connection and capture the communication content because many library functions do not verify the server certificate by default. Many sensitive apps verify the server certificate to ensure that even if the device communication is completely hijacked, the communication data will not be leaked. If the certificate received during the HTTPS handshake is not issued by a specified CA or is not a specified certificate, the communication will be rejected. iOS provides related library functions and sample code to help developers complete this part of the work (0x4). Additionally, several widely used network libraries in iOS also provide corresponding methods to verify server certificates (0x2 and 0x3).

From the perspective of channel attacks, this defense scheme almost completely eliminates the possibility of man-in-the-middle attacks unless the attacker can forge or obtain a certificate for the target server, which is very costly. However, if we have sufficient permissions on the device itself and the target of analysis is the server's processing logic or the communication logic between the server and the client, there are still ways to bypass this detection mechanism.
## 0x1 Summary of Bypass Methods
First, determine the detection mechanism used by the target app. In addition to the methods provided by the official library, third-party network libraries also provide verification interfaces to verify server certificates to prevent man-in-the-middle attacks. The steps are as follows:

1. Hook all functions with the word "Trust" in their names (if the target app's functional functions also contain a lot of "Trust", you need to explore other rules yourself) `python fast_hook_1.py '-[* *Trust*]'`
2. Trigger the function. If the app does not deploy global checks, it is generally deployed in sensitive operations. However, since you already know you need to bypass it, you must know where the checks are performed.
3. Determine the function's parameters and return values, and use Frida to modify the parameters and return values.

In essence, search for all check functions within the target app's space, then dynamically trigger them to locate the specific function. Finally, construct an object that can pass the check to achieve the bypass.

The specific bypass code still needs to be analyzed on a case-by-case basis. Although most check functions are not simple 0/1 return types, you need to construct objects yourself to ensure that subsequent checks pass. Therefore, you need to have a certain understanding of the check code itself. You can find some positive code examples online. Although usually, the verification is a 0/1 return type, some use 0 to indicate pass, and some use 1 to indicate pass. Different library implementations vary.

Based on my own experience, I will introduce a few specific examples.

## 0x2 Alamofire
Test target app: Yangqianbao (version: 3.4.0)

Hook the function `-[NSURLProtectionSpace serverTrust]` and find that it is indeed called. Then use frida-trace to print the call stack and see several very long functions.

```
called from:
0x1009de6b0 Alamofire!_T09Alamofire12TaskDelegateC10urlSessionySo10URLSessionC_So0fB0C4taskSo26URLAuthenticationChallengeC10didReceiveyAF04AuthI11DispositionO_So13URLCredentialCSgtc17completionHandlertF07_T0So10f3C24lim5OSo13N19CSgIyByy_AdGIxyx_TRAnQIyByy_Tf1nnncn_nTf4gggng_n
0x1009ca0ac Alamofire!_T09Alamofire15SessionDelegateC03urlB0ySo10URLSessionC_So0E4TaskC4taskSo26URLAuthenticationChallengeC10didReceiveyAF04AuthI11DispositionO_So13URLCredentialCSgtc17completionHandlertF07_T0So10e3C24lim5OSo13N19CSgIyByy_AdGIxyx_TRAnQIyByy_Tf1nnncn_nTf4gggng_n
0x1009c70bc Alamofire!_T09Alamofire15SessionDelegateC03urlB0ySo10URLSessionC_So0E4TaskC4taskSo26URLAuthenticationChallengeC10didReceiveyAF04AuthI11DispositionO_So13URLCredentialCSgtc17completionHandlertFTo
```

There is an Alamofire keyword, indicating that this library is used. The library itself is developed in Swift. You can find the specific methods inside by opening the dumped Alamofire binary file with IDA. The code that calls `serverTrust` for verification is at the bottom of the call stack (the first function above):

```c
            v63 = objc_msgSend(v7, "protectionSpace");
            v64 = (void *)objc_retainAutoreleasedReturnValue(v63);
            v65 = v64;
            v66 = objc_msgSend(v64, "serverTrust");
            v67 = objc_retainAutoreleasedReturnValue(v66);
            if ( v67 )
            {
              objc_release(v65);
              swift_unknownRetain(v67);
              swift_unknownRetain(v42);
              v68 = ((__int64 (__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64, __int64))_T09Alamofire17ServerTrustPolicyO8evaluateSbSo03SecC0C_SS7forHosttFTf4ggXn_n)(
                      v67,
                      v38,
                      v40,
                      v42,
                      v47,
                      v49,
                      v51);
              swift_unknownRelease(v67);
              swift_unknownRelease(v42);
              if ( v68 & 1 )
              {
                v69 = (void *)objc_allocWithZone(&OBJC_CLASS___NSURLCredential);
                v13 = objc_msgSend(v69, "initWithTrust:", v67);
                swift_unknownRelease(v67);
                if ( (unsigned __int8)v51 == 4 )
                {
                  swift_rt_swift_release(v49);
                }
                else if ( (unsigned __int8)v51 == 3 || (unsigned __int8)v51 == 2 )
                {
                  swift_bridgeObjectRelease(v47);
                }
                swift_unknownRelease(v42);
                v11 = 0LL;
              else
              {
                swift_unknownRelease(v67);
                if ( (unsigned __int8)v51 == 4 )
                {
                  swift_rt_swift_release(v49);
                }
                else if ( (unsigned __int8)v51 == 3 || (unsigned __int8)v51 == 2 )
                {
                  swift_bridgeObjectRelease(v47);
                }
                swift_unknownRelease(v42);
                v13 = 0LL;
                v11 = 2LL;
              }
              goto LABEL_45;
```

You can see that it mainly verifies through another function and then makes an if judgment based on the verification result. If the verification result is 1, then `v11=0`; otherwise, `v13=0` and `v11=2`. The way it calls the verification function is quite special. The specific principle has not been studied, but IDA cannot recognize the function, and Frida cannot find the address of this function, so directly hooking the verification function is temporarily not considered.

The function ends at LABEL_45, with parameters `v5`, `v11`, and `v13`. The parameter affected by the verification is `v11`, and `v13` is the return value, which means other parameters are unrelated to the verification. We focus on the value of `v11`.

```
LABEL_45:
    (*(void (__fastcall **)(__int64, __int64, void *))(v5 + 16))(v5, v11, v13);
    return objc_release(v13);
```

Looking further, if `serverTrust` is 0, meaning the `if(v67)` line is not entered, following the code reveals that `v11=1`. This means `v11` has three values: 0 (pass), 2 (fail), and 1 (unknown). Modify the return value of `serverTrust` to 0 to verify this unknown situation.

The test result shows that it can bypass the verification and continue capturing packets. Since I mainly need to bypass this mechanism to analyze traffic, I did not further study the logic of the function at `v5+16` for the three different `v11` values. If interested, we can discuss it further.

#### Bypass Method
Use Frida to hook the function `-[NSURLProtectionSpace serverTrust]` and modify the return value to 0 to bypass the verification. However, this modification does not make the verification pass but makes it enter another path, so there may be instability, such as some content not displaying correctly.

Core code:

JS part:

```js
function hookObjC(funcname, argNum) {
    var name = funcname;
    resolver.enumerateMatches(name, {
        onMatch: function (match) {
                    send(match.name);
                    Interceptor.attach(match.address,{
                        onEnter: function (args) {
                                argArray[0] = match.name;
                                getObjCArgs(args, argNum);
                        },
        
                        onLeave: function(retval) { 
                            getRetVal(retval);
                            send(argArray);
                            retval.replace(0);
                        }
                    })
        },
        onComplete: function () {}
    });
}
```

Python part:

~~~Python
def rewritesrc():
    ss = ""
    argNum = '-[NSURLProtectionSpace serverTrust]'.count(":")
    ss = src + "setTimeout(function(){"
    ss = ss + "{hookObjC(\"-[NSURLProtectionSpace serverTrust]\", {0})}".format(argNum)
    ss = ss + "}, 0);"
    return ss

def main():
    app = u"Yangqianbao"

    s = frida.get_usb_device().attach(app)
    script = s.create_script(rewritesrc())
    script.on('message', on_msg)
    script.load()

    sys.stdin.read()

def on_msg(msg, data):
    print msg

if __name__ == '__main__':
        main()
~~~

> `python fast_hook_ret_replace_objc.py '-[NSURLProtectionSpace serverTrust]'`

## 0x3 AFSecurityPolicy evaluateServerTrust: forDomain:
Test target: WeBank (version: 2.4.3 (606))

#### Analysis Process
This verification method is implemented in the AF library and slightly modified and incorporated into their SDK in WeBank. You can see the specific code by searching for the function `-[PodWebankSDK_AFSecurityPolicy evaluateServerTrust: forDomain:]`.

Analyzing this function's logic reveals an interesting point. To support more scenarios, the code includes an `allowInvalidCertificates` item, used as shown in the following code (code from IDA F5):

```c
  if ( (unsigned __int64)-[PodWebankSDK_AFSecurityPolicy allowInvalidCertificates](v5, "allowInvalidCertificates") & 1 )
  {
    v42 = 1;
  }
  else
  {
    if ( (unsigned int)SecTrustEvaluate(v4, &v111) )
    {
LABEL_42:
      v42 = 0;
      goto LABEL_75;
    }
    v42 = (_DWORD)v111 == 4 || (_DWORD)v111 == 1;
  }
```

Here, if invalid certificates are allowed, `v42` is directly set to 1, and the final return value is also `v42`. Therefore, it can be quickly determined that the function returns 1 when the certificate verification passes.

#### Bypass Method
Directly use Frida to modify the return value to 1. The code is the same as above, so it will not be posted again. Just change `retval.replace(0)` to `retval.replace(1)` and change the function name.

>`python fast_hook_ret_replace_objc.py '-[PodWebankSDK_AFSecurityPolicy evaluateServerTrust: forDomain:]'`

## 0x4 Non-0/1 Implementation
Test target: Cloud QuickPass (version: v5.0.5)

Through some fancy methods (hooking `serverTrust` and printing the call stack), we found its certificate verification function.
`-[MKNetworkOperation connection: willSendRequestForAuthenticationChallenge:]`

#### Analysis Process

Since it is a standard self-implemented verification, it still calls the system library interface. It is easy to find the shadow of the official sample code in the verification function.

Look at how it handles `serverTrust`.

```
v78 = ((__SecTrust *(__cdecl *)(MKNetworkOperation *, SEL))objc_msgSend)(v4, "serverTrust");
if ( SecTrustGetCertificateCount(v78) < 1 )
{
  v81 = 0LL;
}
else
{
  ((void (__cdecl *)(MKNetworkOperation *, SEL))objc_msgSend)(v4, "serverTrust");
  v79 = SecTrustGetCertificateAtIndex();
  v80 = objc_msgSend(&OBJC_CLASS___NSString, "stringWithFormat:", CFSTR("%@"), v79);
  v81 = (void *)objc_retainAutoreleasedReturnValue(v80);
}
LODWORD(v153) = 0;
objc_msgSend(v81, "rangeOfString:", CFSTR("GeoTrust"));
if ( !v91 )
{
```

Here, after obtaining the `serverTrustRef`, it directly takes the first certificate, then uses `stringWithFormat` to force it into an NSString, and then compares it with a whitelist CA. As long as this comparison passes, the code enters the response phase without any further verification mechanisms.

Since I don't understand what happens when converting non-string types with `stringWithFormat`, I simulated this process with Cycript. The result is as follows (pointer from Frida hook information).

```
cy# a = #0x102855890
#"<cert(0x102855890) s: tysdk.95516.com i: PortSwigger CA>"

cy# [NSString stringWithFormat:"%@",a]
@"<cert(0x102855890) s: tysdk.95516.com i: PortSwigger CA>"
```
This means that this conversion does not involve any intermediate processing and directly outputs the object's description information. The subsequent comparison is to search for the whitelist CA's name in this string.

However, this approach presents an obstacle. If we directly hook the return value of `SecTrustGetCertificateAtIndex`, it may not be possible to extract the certificate correctly. If we hook `-[NSString stringWithFormat:]` or `-[NSString rangeOfString:]`, it may significantly slow down the app. I chose the second option, and despite minimizing the code, the app still had noticeable lag. This area still needs optimization.

Additionally, if you directly use `retval.replace(0x2)` to replace the return value, it will still fail the check.

The specific reason lies in the subsequent comparison code.

```
objc_msgSend(v81, "rangeOfString:", CFSTR("GeoTrust"));
if ( !v91 )
{
  objc_msgSend(v81, "rangeOfString:", CFSTR("VeriSign"));
  if ( !v92 )
  {
    objc_msgSend(v81, "rangeOfString:", CFSTR("Symantec"));
    if ( !v93 )
    {
      objc_msgSend(v81, "rangeOfString:", CFSTR("GlobalSign"));
      if ( !v94 )
      {
        objc_msgSend(v81, "rangeOfString:", CFSTR("Entrust"));
        if ( !v95 )
        {
          objc_msgSend(v81, "rangeOfString:", CFSTR("Thawte"));
          if ( !v96 )
          {
            objc_msgSend(v81, "rangeOfString:", CFSTR("DigiCert"));
            if ( !v97 )
              goto LABEL_77;
          }
        }
      }
    }
  }
}
```

Here, you can see that the values of `v91` to `v97` are unknown, but they are likely related to `rangeOfString:`. Jumping to the assembly code for a closer look (only a segment is captured, other parts are the same except for the target string):

```
__text:00000001003B0A60                 ADRP            X8, #selRef_rangeOfString_@PAGE
__text:00000001003B0A64                 LDR             X21, [X8,#selRef_rangeOfString_@PAGEOFF]
__text:00000001003B0A68                 ADRP            X2, #cfstr_Geotrust@PAGE ; "GeoTrust"
__text:00000001003B0A6C                 ADD             X2, X2, #cfstr_Geotrust@PAGEOFF ; "GeoTrust"
__text:00000001003B0A70                 MOV             X0, X23 ; void *
__text:00000001003B0A74                 MOV             X1, X21 ; char *
__text:00000001003B0A78                 BL              _objc_msgSend
__text:00000001003B0A7C                 CBNZ            X1, loc_1003B0B10
```

The parameters are passed normally, but the jump condition uses `X1` instead of the return value `X0`. The default return value is `X0`, and `retval.replace` naturally replaces `X0`, explaining why direct replacement is ineffective.

Understanding the reason, handling it is not difficult. The specific bypass is described in the next section.

> PS: This app has a loop detection. If you can find the trigger point, hook it to solve the performance issue. However, even without it, the delay on an iPhone 6 (10.2.1) is not significant. It depends on personal needs.

#### Bypass Method

> PS: The app has a loop detection. If you can find the trigger point, hook it to solve the performance issue. However, even without it, the delay on an iPhone 6 (10.2.1) is not significant. It depends on personal needs.

There are two options: one is to construct a complete cert object and modify the return value of `SecTrustGetCertificateAtIndex`, which has minimal impact on system speed. However, constructing this object is a cumbersome process. The second option is to hook the relevant NSString methods. I hooked `-[NSString rangeOfString:]`, checking the first parameter. If it contains "Charles" (my packet capture tool CA, because the app's server requires a 2048-bit certificate, and Burp's default certificate is 1024-bit, causing some packet capture failures), modify `X1` and `X0` (for safety) in `onLeave`.

Core code:

JS part:

```js
function hookObjC(funcname, argNum) {
    var name = funcname;
    resolver.enumerateMatches(name, {
        onMatch: function (match) {
                    send(match.name);
                    var flag = 0;
                    var edit_cnt = 1;
                    var NSString = ObjC.classes.NSString;
                    ps = NSString.stringWithString_("Charles"); // If you use Burp, replace Charles with PortSwigger. And you may need to generate a 2048bits cert.

                    Interceptor.attach(match.address,{
                        onEnter: function (args) {
                                //if(edit_cnt < 3){
                                    tmp = ObjC.Object(args[0]);
                                    if(tmp.containsString_(ps)){
                                        console.log("HTTP Pinning detected. ", edit_cnt, " times.");
                                        if(flag == 0)
                                            flag = 1;
                                    }
                                //}
                        },

                        onLeave: function(retval) { 
                            if(flag == 1){
                               console.log("Bypassed.");
                               this.context['x1'] = 0x25;
                               retval.replace(0x25);
                               flag = 0;
                               edit_cnt = edit_cnt + 1;
                            }
                        }
                    })
        },
        onComplete: function () {}
    });
}
```

Python part:

```
def rewritesrc(funcname):
    ss = ""
    argNum = funcname.count(":")
    ss = src + "setTimeout(function(){"
    ss = ss + "{hookObjC(\"{0}\", {1})}".format(funcname, argNum)
    ss = ss + "}, 0);"

    return ss

def main():
    app = u"Cloud QuickPass"

    s = frida.get_usb_device().attach(app)
    script = s.create_script(rewritesrc("-[NSString rangeOfString:]"))
    script.on('message', on_msg)
    script.load()

    sys.stdin.read()

def on_msg(msg, data):
    print msg
```
