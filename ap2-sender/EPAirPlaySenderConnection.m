//
//  EPAirPlaySenderConnection.m
//  ap2-sender
//
//  Created by Viktoriia on 14.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import "AirPlaySenderConnection.h"
#import "EPUserDefaults.h"
#import "AirPlayConstants.h"
#import "DeclarationsNMacroses.h"
#import "CocoaAdditions.h"

#import "DDData.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import "srp.h"
#import "ed25519.h"
#import <openssl/evp.h>

#import "TLV8.h"
#import "NSArray+TLV8Additions.h"
#import "sha.h"
#import "chachapoly.h"

#ifndef APPSTATICO_DISABLED
#import "Appstatico.h"
#import "AppstaticoEvents.h"
#endif

#ifndef EVP_CTRL_GCM_GET_TAG
#define EVP_CTRL_GCM_GET_TAG 0x10
#endif

#ifndef EVP_CTRL_GCM_SET_IVLEN
#define EVP_CTRL_GCM_SET_IVLEN 0x9
#endif

#define MAX_BLOCK_LENGTH 0x400

void hexdump(char *msg, unsigned char *dword, int len) {
    printf("%s", msg);
    for (int i = 0; i < len; i++) {
        if ((i != 0) && (i % 16 == 0)) {
            printf("\n");
        }
        printf("%02x ", dword[i]);
    }
        
    printf("\n\n");
}

@interface AirPlaySenderConnection () <NSStreamDelegate> {
    NSString            *_appleDeviceID;
    NSString            *_hostAddress;
    NSString            *_hostName;
    int                 _port;
    NSInputStream       *_inputStream;
    NSOutputStream      *_outputStream;
    NSMutableData       *_inputBuffer;
    NSMutableArray      *_previouslyUsedPasswords;

    NSMutableArray      *_dataWriteQueue;
    int                 _currentDataOffset;
    BOOL                _canSendDirectly;

    //Pairing
    struct              SRPUser *_user;
    
    id<AirPlaySenderConnectionDelegate> __weak delegate;
}

@property (strong) NSData *accessoryLtpk;
@property (strong) NSData *accessory_curve_public;
@property (strong) NSData *accessory_shared_key;
@property (assign, getter=isEncrypted) BOOL encrypted;
@property (assign) int out_count;
@property (assign) int in_count;

@property (strong) NSData *outgoing_key;
@property (strong) NSData *incoming_key;

@end

@implementation AirPlaySenderConnection

- (id)initWithHostAddress:(NSString *)address name:(NSString *)name port:(int)port deviceID:(NSString *)deviceID {
    self = [super init];
    if (self) {
        _appleDeviceID = deviceID;
        _hostAddress = address;
        _hostName = name;
        _port = port;
        _setuped = NO;
        
        _previouslyUsedPasswords = [[NSMutableArray alloc] init];
        _dataWriteQueue = [[NSMutableArray alloc] init];
        _currentDataOffset = 0;
        _canSendDirectly = NO;
        
        _state = EPAirPlaySenderStateNotConnected;
        _protocolVersion = 1;
        _airPlay2Supported = NO;
        
        //Pairing
        _user = NULL;
        //Keys used for pairing
        _authSecretData = nil;
        _authPrivateKeyData = nil;
        _authPublicKeyData = nil;
        //Keys used for verifying existing pairing
        _verifierPrivateKeyData = nil;
        _verifierPublicKeyData = nil;
        
        _encrypted = NO;
        _out_count = 0;
        _in_count = 0;
    }
    return self;
}

- (id)delegate {
    return delegate;
}

- (void)setDelegate:(id)value {
    delegate = value;
}

- (void)setup {
    _setuped = NO;
    if (_previouslyUsedPasswords.count > 0) {
        [_previouslyUsedPasswords removeAllObjects];
    }
    
    if (_dataWriteQueue && _dataWriteQueue.count > 0) {
        [_dataWriteQueue removeAllObjects];
        _currentDataOffset = 0;
    }
    _canSendDirectly = NO;
    self.state = EPAirPlaySenderStateNotConnected;
    
    //Creates readable and writable streams connected to a socket.
    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;
    CFStringRef hostname = NULL;
    if (!_hostName || [EPUserDefaults isIPAddressPreferredOverHostName]) {
        NSURL *serverURL = [NSURL URLWithString:[NSString stringWithFormat:@"http://%@", _hostAddress]];
        hostname = (__bridge CFStringRef)[serverURL host];
    } else {
        hostname =  (__bridge CFStringRef)_hostName;
    }
    CFStreamCreatePairWithSocketToHost(kCFAllocatorDefault, hostname, _port, &readStream, &writeStream);
    EPAirPlaySenderLog(@"[AirPlay] Connecting to %@ (%@) at port %d...", _hostName, _hostAddress, _port);
    
    //Cast these objects to an NSInputStream and an NSOutputStream
    _inputStream = (__bridge_transfer NSInputStream *)readStream;
    _outputStream = (__bridge_transfer NSOutputStream *)writeStream;
    
    //Once you have cast the CFStreams to NSStreams, set the delegate, schedule the stream on a run loop, and open the stream as usual.
    //The delegate should begin to receive stream-event messages (stream:handleEvent:)
    [_inputStream setDelegate:self];
    [_outputStream setDelegate:self];
    [_inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [_outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [_inputStream open];
    [_outputStream open];
}

- (void)close {
    [_inputStream close];
    [_outputStream close];
    [_inputStream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [_outputStream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [_inputStream setDelegate:nil];
    [_outputStream setDelegate:nil];
    _inputStream = nil;
    _outputStream = nil;
}

#pragma mark - NSStreamDelegate Protocol Support

- (void)stream:(NSStream *)stream handleEvent:(NSStreamEvent)event {
    id __weak wself = self;
    switch (event) {
        case NSStreamEventOpenCompleted:
            EPAirPlaySenderLog(@"[Socket] The open has completed successfully.");
            break;
        case NSStreamEventHasSpaceAvailable:
#ifdef AIRPLAY_LOG
            NSLog(@"[Socket] The stream can accept bytes for writing.");
#endif
            [self _sendData];
            break;
        case NSStreamEventHasBytesAvailable:;
#ifdef AIRPLAY_LOG
            NSLog(@"[Socket] The stream has bytes to be read.");
#endif
            uint8_t buf[16 * 1024];
            uint8_t *buffer = NULL;
            NSUInteger len = 0;
            //Returns by reference a pointer to a read buffer and, by reference,
            //the number of bytes available, and returns a Boolean value that
            //indicates whether the buffer is available.
            if (![_inputStream getBuffer:&buffer length:&len]) {
                //Reads up to a given number of bytes into a given buffer.
                //Returns a number indicating the outcome of the operation:
                //  A positive number indicates the number of bytes read;
                //  0 indicates that the end of the buffer was reached;
                //  A negative number means that the operation failed.
                NSInteger amount = [_inputStream read:buf maxLength:sizeof(buf)];
                buffer = buf;
                len = amount;
            }
            if (0 < len) {
                if (!_inputBuffer) {
                    _inputBuffer = [[NSMutableData alloc] init];
                }
                @try {
                    [_inputBuffer appendBytes:buffer length:len];
                }
                @catch (NSException *exception) {
                    NSLog(@"Exception was thrown: %@.", exception.description);
                }
            }
            do {} while ([wself processIncomingBytes]);
            break;
        case NSStreamEventErrorOccurred:
        {
            NSError *streamError = [stream streamError];
            NSLog(@"[Socket] An error %ld has occurred on the stream: %@.", (long)streamError.code, streamError.description);
            break;
        }
        case NSStreamEventEndEncountered:
        {
            NSLog(@"[Socket] The end of the stream has been reached.");
            if (delegate && [delegate respondsToSelector:@selector(playbackStateDidChange:userInfo:)]) {
                [delegate playbackStateDidChange:AIRPLAY_PLAYBACK_STATE_STOPPED userInfo:nil];
            }
            break;
        }
        default:
            break;
    }
}

// YES return means that a complete request was parsed, and the caller
// should call again as the buffered bytes may have another complete
// request available.
- (BOOL)processIncomingBytes {
    if (self.isEncrypted) {
        NSUInteger len = [_inputBuffer length];
        NSLog(@"received %lu bytes", (unsigned long)len);
        if (len > 0) {
            unsigned short data_len = 0;
            [_inputBuffer getBytes:&data_len length:sizeof(_inputBuffer)];
            if (data_len > 0) {
                unsigned long long c = (unsigned long long)self.in_count;
                unsigned long long *in_count_bytes = &c;
                unsigned char *nonce = (unsigned char *)malloc(12);
                memset(nonce, 0, 12);
                memcpy(&nonce[4], in_count_bytes, 8);
                
                unsigned short *bytes = (unsigned short *)&data_len;
                NSData *lengthData = [NSData dataWithBytes:bytes length:sizeof(unsigned short)];
                NSData *blockData = [_inputBuffer subdataWithRange:NSMakeRange(2, data_len)];
                NSData *tagData = [_inputBuffer subdataWithRange:NSMakeRange(data_len+2, 16)];
                
                unsigned char ct[1000];
                
                //out_cipher = ChaCha20_Poly1305.new(key=self.outgoing_key, nonce=nonce)
                //out_cipher.update(struct.pack("H", length))
                //enc, tag = out_cipher.encrypt_and_digest(block)
                struct chachapoly_ctx ctx;
                chachapoly_init(&ctx, self.incoming_key.bytes, 256);
                if (chachapoly_crypt(&ctx, nonce, lengthData.bytes, (int)lengthData.length, (void *)blockData.bytes, (int)blockData.length, ct, (void *)tagData.bytes, 16, 0) == 0) {
//                    if (memcmp(ct, "RTSP", sizeof("RTSP")) == 0) {
                        memcpy(ct, "HTTP", sizeof("RTSP")-1);
//                    }
                    CFHTTPMessageRef message = CFHTTPMessageCreateEmpty(kCFAllocatorDefault, false);
                    CFHTTPMessageAppendBytes(message, ct, data_len);
                    
                    if (CFHTTPMessageIsHeaderComplete(message)) {
                        self.in_count++;
                        
                        NSString *contentLengthValue = (__bridge_transfer NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Length");
                        unsigned contentLength = contentLengthValue ? [contentLengthValue intValue] : 0;
                        NSData *body = (__bridge_transfer NSData *)CFHTTPMessageCopyBody(message);
                        NSUInteger bodyLength = [body length];
                        if (contentLength <= bodyLength) {
                            NSData *newBody = [NSData dataWithBytes:[body bytes] length:contentLength];
                            [_inputBuffer setLength:0];
                            [_inputBuffer appendBytes:([body bytes] + contentLength) length:(bodyLength - contentLength)];
                            CFHTTPMessageSetBody(message, (__bridge CFDataRef)newBody);
                        } else {
                            CFRelease(message);
                            return NO;
                        }
                        
#ifdef AIRPLAY_LOG
                        [self printHTTPMessage:message];
#endif
                            
                        long responseStatusCode = CFHTTPMessageGetResponseStatusCode(message);
                        if (contentLength != 0) {
                            NSString *contentTypeValue = (__bridge_transfer NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Type");
                            if ([contentTypeValue isEqualToString:@"application/x-apple-binary-plist"]) {
                                NSData *requestBody = (__bridge_transfer NSData *)CFHTTPMessageCopyBody(message);
                                NSPropertyListFormat format;
                                NSError *error = nil;
                                NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:requestBody options:NSPropertyListImmutable format:&format error:&error];
                                NSLog(@"%@", plist.debugDescription);
                                if ([plist objectForKey:@"uiPreloaded"]) {
                                }
                            }
                        }
                        
                    } else {
                        CFRelease(message);
                        return NO;
                    }
                }
            }
        }
        return NO;
    }
    
    BOOL isRequest = [self isResponseReceived] ? FALSE : TRUE;
    CFHTTPMessageRef message = CFHTTPMessageCreateEmpty(kCFAllocatorDefault, isRequest);
    CFHTTPMessageAppendBytes(message, [_inputBuffer bytes], [_inputBuffer length]);
    
    if (CFHTTPMessageIsHeaderComplete(message)) {
        NSString *contentLengthValue = (__bridge_transfer NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Length");
        
        unsigned contentLength = contentLengthValue ? [contentLengthValue intValue] : 0;
        NSData *body = (__bridge_transfer NSData *)CFHTTPMessageCopyBody(message);
        NSUInteger bodyLength = [body length];
        if (contentLength <= bodyLength) {
            NSData *newBody = [NSData dataWithBytes:[body bytes] length:contentLength];
            [_inputBuffer setLength:0];
            [_inputBuffer appendBytes:([body bytes] + contentLength) length:(bodyLength - contentLength)];
            CFHTTPMessageSetBody(message, (__bridge CFDataRef)newBody);
        } else {
            CFRelease(message);
            return NO;
        }
    } else {
        CFRelease(message);
        return NO;
    }
    
#ifdef AIRPLAY_LOG
    [self printHTTPMessage:message];
#endif
    
    if (!isRequest) {
        long responseStatusCode = CFHTTPMessageGetResponseStatusCode(message);
        
#if 0
        if (responseStatusCode == 401) { //HTTP/1.1 401 Unauthorized
            [self handleAuthenticationFailureResponse:message];
            CFRelease(message);
            return YES;
        }
        
        if (responseStatusCode == 453) { //HTTP/1.1 453 Not Enough Bandwidth
            if (delegate && [delegate respondsToSelector:@selector(handleNotEnoughBandwidthResponse)]) {
                [delegate handleNotEnoughBandwidthResponse];
            }
            CFRelease(message);
            return YES;
        }
        
        if (responseStatusCode == 470 || (responseStatusCode == 500 && self.state == EPAirPlaySenderStateWaitingOnPairSetup2)) {
            //HTTP/1.1 470 Connection Authorization Required
            //HTTP/1.1 500 Internal Server Error
            NSString *password = nil;
            if (delegate && [delegate respondsToSelector:@selector(passwordDistinctFromPrevious:)]) {
                password = [delegate passwordDistinctFromPrevious:_previouslyUsedPasswords];
            }
            if (password != nil) {
                [_previouslyUsedPasswords addObject:password];
                [self doPairing:password];
            }
            CFRelease(message);
            return YES;
        }
        
        if (responseStatusCode == 500 && self.state == EPAirPlaySenderStateWaitingOnPairVerify1) {
            [self startPairing];
            CFRelease(message);
            return YES;
        }
        
        if (responseStatusCode == 500) {
//            NSLog(@"HTTP/1.1 500 Internal Server Error");
            [self resumeWithCredentials:nil];
            CFRelease(message);
            return YES;
        }
        
        if (responseStatusCode == 200 && self.state != EPAirPlaySenderStateReadyToPlay) {
            if (self.state == EPAirPlaySenderStateWaitingOnPairPinStart) {
                //Request a pin.
//                NSLog(@"Is main thread: %d", [NSThread isMainThread]);
                NSString *password = nil;
                if (delegate && [delegate respondsToSelector:@selector(passwordDistinctFromPrevious:)]) {
                    password = [delegate passwordDistinctFromPrevious:_previouslyUsedPasswords];
                }
                [self doPairing:password];
                CFRelease(message);
                return YES;
            }
            
            if (self.state == EPAirPlaySenderStateWaitingOnPairVerify2) {
                EPAirPlaySenderLog(@"Verification complete!");
#ifndef APPSTATICO_DISABLED
                [Appstatico sendEvent:AppstaticoEventAirPlayPairingComplete withStringValue:@""];
#endif
                self.state = EPAirPlaySenderStateReadyToPlay;
                [self pairingDidFinish];
                CFRelease(message);
                return YES;
            }
            
            //Gets the body from a CFHTTPMessage object.
            NSString *contentLengthValue = (__bridge_transfer NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Length");
            unsigned contentLength = contentLengthValue ? [contentLengthValue intValue] : 0;
            if (contentLength != 0) {
                NSString *contentTypeValue = (__bridge_transfer NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Type");
                if ([contentTypeValue isEqualToString:@"application/x-apple-binary-plist"])
                {
                    NSData *requestBody = (__bridge_transfer NSData *)CFHTTPMessageCopyBody(message);
                    NSPropertyListFormat format;
                    NSError *error = nil;
                    NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:requestBody options:NSPropertyListImmutable format:&format error:&error];
                    if (plist == nil) {
                    } else {
                        id pk = [plist objectForKey:@"pk"]; //256 bytes
                        id salt = [plist objectForKey:@"salt"]; //16 bytes
                        if (pk != nil && salt != nil) {
#ifdef AIRPLAY_LOG
                            NSLog(@"pk and salt received!");
#endif
                            if ([pk isKindOfClass:[NSData class]] && [salt isKindOfClass:[NSData class]]) {
                                NSData *pkData = (NSData *)pk;
                                NSData *saltData = (NSData *)salt;
#ifdef AIRPLAY_LOG
                                NSLog(@"pk - %ld bytes, salt - %ld bytes", pkData.length, saltData.length);
#endif
                                [self doPairSetupPin2WithServerPublicKey:pkData salt:saltData];
                            }
                        } else {
                            id proof = [plist objectForKey:@"proof"];
                            if (proof != nil) {
#ifdef AIRPLAY_LOG
                                NSLog(@"proof received!");
#endif
                                if ([proof isKindOfClass:[NSData class]]) {
                                    NSData *proofData = (NSData *)proof;
#ifdef AIRPLAY_LOG
                                    NSLog(@"proof - %ld bytes", proofData.length);
#endif
                                    [self doPairSetupPin3WithServerProof:proofData];
                                }
                            } else {
                                id epk = [plist objectForKey:@"epk"];
                                id authTag = [plist objectForKey:@"authTag"];
                                if (epk != nil && authTag != nil) {
#ifdef AIRPLAY_LOG
                                    NSLog(@"epk and authTag received! Pairing complete.");
#endif
                                    if ([epk isKindOfClass:[NSData class]] && [authTag isKindOfClass:[NSData class]]) {
#ifdef AIRPLAY_LOG
                                        NSData *epkData = (NSData *)epk;
                                        NSData *authTagData = (NSData *)authTag;
                                        NSLog(@"epk - %ld bytes, authTag - %ld bytes", epkData.length, authTagData.length);
#endif
                                        //auth_secret <a> is now registered in the AppleTV as a valid secret
                                        if (self.delegate && [self.delegate respondsToSelector:@selector(saveAuthenticationData:)]) {
                                            [self.delegate saveAuthenticationData:self.authSecretData];
                                        }
                                        [self doPairVerify1];
                                    }
                                }
                            }
                        }
                    }
                }
                else if ([contentTypeValue isEqualToString:@"application/octet-stream"])
                {
#ifdef AIRPLAY_LOG
                    NSLog(@"application/octet-stream received.");
#endif
                    if (self.state == EPAirPlaySenderStateWaitingOnPairVerify1) {
                        NSData *requestBody = (__bridge_transfer NSData *)CFHTTPMessageCopyBody(message);
                        [self doPairVerify2WithData:requestBody];
                    }
                }
            }
            
            CFRelease(message);
            return YES;
        }
#else
        if (responseStatusCode == 200 && self.state != EPAirPlaySenderStateReadyToPlay) {
            if (self.state == EPAirPlaySenderStateWaitingOnPairPinStart) {
                //Request a pin.
                NSString *password = nil;
                if (delegate && [delegate respondsToSelector:@selector(passwordDistinctFromPrevious:)]) {
                    password = [delegate passwordDistinctFromPrevious:_previouslyUsedPasswords];
                }
                [self handlePairSetup:password];
                CFRelease(message);
                return YES;
            }
            
            if (self.state == EPAirPlaySenderStateWaitingOnPairVerify2) {
                EPAirPlaySenderLog(@"Verification complete!");
                self.encrypted = YES;
                
                [self setCiphers];
                
#ifndef APPSTATICO_DISABLED
                [Appstatico sendEvent:AppstaticoEventAirPlayPairingComplete withStringValue:@""];
#endif
                self.state = EPAirPlaySenderStateReadyToPlay;
                [self pairingDidFinish];
                CFRelease(message);
                return YES;
            }
            
            //Gets the body from a CFHTTPMessage object.
            NSString *contentLengthValue = (__bridge_transfer NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Length");
            unsigned contentLength = contentLengthValue ? [contentLengthValue intValue] : 0;
            if (contentLength != 0) {
//                NSString *contentTypeValue = (__bridge_transfer NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Type");
//                if ([contentTypeValue isEqualToString:@"application/octet-stream"]) {
//#ifdef AIRPLAY_LOG
//                    NSLog(@"application/octet-stream received.");
//#endif
                    NSData *requestBody = (__bridge_transfer NSData *)CFHTTPMessageCopyBody(message);
                    [self pair_setup:requestBody];
//                }
            }
            
            CFRelease(message);
            return YES;
        }
#endif
    }
    
    [self handleMessage:message];
    CFRelease(message);
    
    return YES;
}

//- (void)writeOut:(NSString *)message {
//#ifdef AIRPLAY_LOG
//    NSLog(@"\n\nCLIENT -> SERVER:\n%@", message);
//#endif
//    if (message == nil) {
//        return;
//    }
////    NSData *requestData = [message dataUsingEncoding:NSUTF8StringEncoding];
////    [asyncSocket writeData:requestData withTimeout:-1.0 tag:0];
//    // writes the bytes from the specified buffer to the stream up to len bytes. Returns the number of bytes actually written.
//    uint8_t *buf = (uint8_t *)[message UTF8String];
//    NSInteger written = [outputStream write:buf maxLength:strlen((char *)buf)];
//#ifdef AIRPLAY_LOG
//    NSLog(@"Written %ld of %lu bytes.", (long)written, strlen((char *)buf));
//#endif
//}

// Public interface for sending data.
- (void)sendData:(NSData *)data {
#ifdef AIRPLAY_LOG
    NSLog(@"%s", __PRETTY_FUNCTION__);
#endif
    
    if (!self.isEncrypted) {
        [_dataWriteQueue insertObject:data atIndex:0];
    } else {
        //Encrypt and send the given data
        NSData *encryptedData = [self encryptData:data];
        [_dataWriteQueue insertObject:encryptedData atIndex:0];
    }
    if (_canSendDirectly) [self _sendData];
}

// Private
- (void)_sendData {
#ifdef AIRPLAY_LOG
    NSLog(@"%s", __PRETTY_FUNCTION__);
#endif
    _canSendDirectly = NO;
    NSData *data = [_dataWriteQueue lastObject];
    if (data == nil) {
        _canSendDirectly = YES;
        return;
    }
    uint8_t *readBytes = (uint8_t *)[data bytes];
    readBytes += _currentDataOffset;
    NSUInteger dataLength = [data length];
    NSUInteger lengthOfDataToWrite = (dataLength - _currentDataOffset >= 1024) ? 1024 : (dataLength - _currentDataOffset);
    NSInteger bytesWritten = [_outputStream write:readBytes maxLength:lengthOfDataToWrite];
#ifdef AIRPLAY_LOG
    NSLog(@"%s: %ld bytes written", __PRETTY_FUNCTION__, (long)bytesWritten);
#endif
    if (bytesWritten > 0) {
        _currentDataOffset += bytesWritten;
        if (_currentDataOffset == dataLength) {
            [_dataWriteQueue removeLastObject];
            _currentDataOffset = 0;
        }
    }
}


#pragma mark -
#pragma mark Override
- (void)handleMessage:(CFHTTPMessageRef)message {
    
}

- (void)resumeWithCredentials:(NSString *)credentials {
    
}

- (BOOL)isResponseReceived {
    return YES;
}

- (NSString *)uri {
    return nil;
}

#pragma mark -
#pragma mark Handling authentication failure
- (void)handleAuthenticationFailureResponse:(CFHTTPMessageRef)message {
    //HTTP/1.1 401 Unauthorized
    //Www-Authenticate: Digest realm="airplay", nonce="1f9e1c6b5a35b7d20628025b18438324"
    //Server: AirTunes/220.68
    //Content-Length: 0
    //Date: Fri, 15 Jan 2016 13:02:19 GMT
    NSString *authenticationHeader = (__bridge_transfer NSString *)(CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Www-Authenticate"));
    NSString *realm = [self quotedSubHeaderFieldValue:@"realm" fromHeaderFieldValue:authenticationHeader];
    NSString *nonce = [self quotedSubHeaderFieldValue:@"nonce" fromHeaderFieldValue:authenticationHeader];
    NSString *username = @"AirPlay";
    NSString *password = nil;
    if (delegate && [delegate respondsToSelector:@selector(passwordDistinctFromPrevious:)]) {
        password = [delegate passwordDistinctFromPrevious:_previouslyUsedPasswords];
    }
    if (password == nil)
        return;
    else
        [_previouslyUsedPasswords addObject:password];
    NSString *HA1str = [NSString stringWithFormat:@"%@:%@:%@", username, realm, password];
    NSString *method = @"POST";
    NSString *uri = [self uri];
    if (uri == nil)
        return;
    NSString *HA2str = [NSString stringWithFormat:@"%@:%@", method, uri];
    NSString *HA1 = [[[HA1str dataUsingEncoding:NSUTF8StringEncoding] md5Digest] hexStringValue];
    NSString *HA2 = [[[HA2str dataUsingEncoding:NSUTF8StringEncoding] md5Digest] hexStringValue];
    NSString *responseStr = nil;
    responseStr = [NSString stringWithFormat:@"%@:%@:%@", HA1, nonce, HA2];
    NSString *response = [[[responseStr dataUsingEncoding:NSUTF8StringEncoding] md5Digest] hexStringValue];
    NSString *authorization = [NSString stringWithFormat:@"Digest username=\"%@\", realm=\"%@\", nonce=\"%@\", uri=\"%@\", response=\"%@\"",
                               username, realm, nonce, uri, response];
    [self resumeWithCredentials:authorization];
}

#pragma mark -
#pragma mark Helpers
- (NSString *)quotedSubHeaderFieldValue:(NSString *)param fromHeaderFieldValue:(NSString *)header {
    NSRange startRange = [header rangeOfString:[NSString stringWithFormat:@"%@=\"", param]];
    if(startRange.location == NSNotFound)
    {
        // The param was not found anywhere in the header
        return nil;
    }
    
    NSUInteger postStartRangeLocation = startRange.location + startRange.length;
    NSUInteger postStartRangeLength = [header length] - postStartRangeLocation;
    NSRange postStartRange = NSMakeRange(postStartRangeLocation, postStartRangeLength);
    
    NSRange endRange = [header rangeOfString:@"\"" options:0 range:postStartRange];
    if(endRange.location == NSNotFound)
    {
        // The ending double-quote was not found anywhere in the header
        return nil;
    }
    
    NSRange subHeaderRange = NSMakeRange(postStartRangeLocation, endRange.location - postStartRangeLocation);
    return [header substringWithRange:subHeaderRange];
}

#pragma mark -
#pragma mark POST/GET
//Executes a POST to a resource
- (void)post:(NSString *)resource {
    NSDictionary *headers = @{@"Content-Length":@"0"};
    [self post:resource body:nil headers:headers];
}

- (void)post:(NSString *)resource body:(NSData *)bodyData headers:(NSDictionary *)requestHeaders {
    CFStringRef requestMethod = CFSTR("POST");
    [self prepareRequest:requestMethod resource:resource body:bodyData headers:requestHeaders];
}

//Executes a GET to a resource
- (void)get:(NSString *)resource {
    CFStringRef requestMethod = CFSTR("GET");
    [self prepareRequest:requestMethod resource:resource body:nil headers:nil];
}

- (void)prepareRequest:(CFStringRef)requestMethod resource:(NSString *)resource body:(NSData *)bodyData headers:(NSDictionary *)requestHeaders {
    CFStringRef requestURLString = (__bridge CFStringRef)resource;
    CFURLRef requestURL = CFURLCreateWithString(kCFAllocatorDefault, requestURLString, NULL);
    CFHTTPMessageRef request = CFHTTPMessageCreateRequest(kCFAllocatorDefault, requestMethod, requestURL, kCFHTTPVersion1_1);
    if (bodyData != nil) {
        CFHTTPMessageSetBody(request, (__bridge CFDataRef)bodyData);
    }
    [self sendRequest:request headers:requestHeaders];
    CFRelease(requestURL);
    CFRelease(request);
}

- (void)sendRequest:(CFHTTPMessageRef)request headers:(NSDictionary *)requestHeaders {
    //The defaults connection headers
    CFHTTPMessageSetHeaderFieldValue(request, (CFStringRef)@"User-Agent", (CFStringRef)@"AirPlay/381.13");//AirPlay/320.20
    CFHTTPMessageSetHeaderFieldValue(request, (CFStringRef)@"X-Apple-HKP", (CFStringRef)@"3");
//    CFHTTPMessageSetHeaderFieldValue(request, (CFStringRef)@"X-Apple-Device-ID", (__bridge CFStringRef)_appleDeviceID);
//    CFHTTPMessageSetHeaderFieldValue(request, (CFStringRef)@"X-Apple-Session-ID", (CFStringRef)sessionID);
//    CFHTTPMessageSetHeaderFieldValue(request, (CFStringRef)@"Connection", (CFStringRef)@"keep-alive");
    
    //optional headers
    if (requestHeaders != nil) {
        for (NSString *headerName in requestHeaders) {
            CFHTTPMessageSetHeaderFieldValue(request, (__bridge CFStringRef)headerName, (__bridge CFStringRef)[requestHeaders objectForKey:headerName]);
        }
    }
    
#ifdef AIRPLAY_LOG
    [self printHTTPMessage:request];
#endif
    
    //Serializes a CFHTTPMessage object
    NSData *serializedMsg = (__bridge_transfer NSData *)CFHTTPMessageCopySerializedMessage(request);
    [self sendData:serializedMsg];
}

/**
 * Gets the current date and time, formatted properly (according to RFC) for insertion into an HTTP header.
 **/
- (NSString *)dateAsString:(NSDate *)date {
    // Example: Sun, 06 Nov 1994 08:49:37 GMT
    
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    [df setFormatterBehavior:NSDateFormatterBehavior10_4];
    [df setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"GMT"]];
    [df setDateFormat:@"EEE, dd MMM y HH:mm:ss 'GMT'"];
    
    // For some reason, using zzz in the format string produces GMT+00:00
    
    return [df stringFromDate:date];
}

#pragma mark -
#pragma mark ATV Device Verification Support

- (void)startPairing {
    self.state = EPAirPlaySenderStateWaitingOnPairPinStart;
    [self post:@"/pair-pin-start"];
}

- (void)doPairing:(NSString *)pin {
    if (pin == nil) {
#ifdef AIRPLAY_LOG
        NSLog(@"Pairing cancelled by user (pin is nil).");
#endif
        self.state = EPAirPlaySenderStateCancelled;
        return;
    }
    self.state = EPAirPlaySenderStateWaitingOnPairSetup1;
    
    NSString *clientId = _appleDeviceID;
    const char *passwordChar = pin.UTF8String;
    size_t passwordLength = strlen(passwordChar);
    _user = srp_user_new(SRP_SHA1, SRP_NG_2048, clientId.UTF8String, (const unsigned char *)passwordChar, (int)passwordLength, 0, 0);
    NSDictionary *plist = @{@"method": @"pin",
                            @"user": clientId};
    
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:plist format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/x-apple-binary-plist" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)data.length] forKey:@"Content-Length"];
    [self post:@"/pair-setup-pin" body:data headers:headers];
}

- (void)doPairSetupPin2WithServerPublicKey:(NSData *)pk salt:(NSData *)salt {
    self.state = EPAirPlaySenderStateWaitingOnPairSetup2;
    
    // Calculate public client value and client evidence
    const char *auth_username = 0;
    const unsigned char *pkA;
    int pkA_len;
    const unsigned char *M1;
    int M1_len;
    
    // Calculate A
    srp_user_start_authentication(_user, &auth_username, &pkA, &pkA_len);
    
    // Calculate M1 (client proof)
    srp_user_process_challenge(_user, salt.bytes, (int)salt.length, pk.bytes, (int)pk.length, &M1, &M1_len);
//    NSLog(@"A: %s (%d bytes)", pkA, pkA_len);
//    NSLog(@"M1: %s (%d bytes)", M1, M1_len);
    
    NSDictionary *plist = @{@"pk": [NSData dataWithBytes:pkA length:pkA_len],
                            @"proof": [NSData dataWithBytes:M1 length:M1_len]};
    
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:plist format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/x-apple-binary-plist" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)data.length] forKey:@"Content-Length"];
    [self post:@"/pair-setup-pin" body:data headers:headers];
}

- (void)doPairSetupPin3WithServerProof:(NSData *)proof {
    self.state = EPAirPlaySenderStateWaitingOnPairSetup3;
    
    // Check M2
    srp_user_verify_session(_user, proof.bytes);
    if (!srp_user_is_authenticated(_user)) {
        NSLog(@"AirPlay: Server authentication failed.");
        return;
    }
    
    int sessionKeyLen = 0;
    const unsigned char *sessionKey = srp_user_get_session_key(_user, &sessionKeyLen);
    if (!sessionKey) {
        NSLog(@"AirPlay: No valid session key.");
        return;
    }
    
    const void *pairSetupAesKey = "Pair-Setup-AES-Key";
    const void *pairSetupAesIV = "Pair-Setup-AES-IV";
    
    unsigned char hash[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512_CTX context;
    CC_SHA512_Init(&context);
    CC_SHA512_Update(&context, pairSetupAesKey, (CC_LONG)strlen(pairSetupAesKey));
    CC_SHA512_Update(&context, sessionKey, (CC_LONG)sessionKeyLen);
    CC_SHA512_Final(hash, &context);
    
    unsigned char aesKey[16];
    memcpy(aesKey, hash, 16);
    
    CC_SHA512_Init(&context);
    CC_SHA512_Update(&context, pairSetupAesIV, (CC_LONG)strlen(pairSetupAesIV));
    CC_SHA512_Update(&context, sessionKey, (CC_LONG)sessionKeyLen);
    CC_SHA512_Final(hash, &context);
    
    unsigned char aesIV[16];
    memcpy(aesIV, hash, 16);
    aesIV[15]++;
    
    //Create a random seed (auth_secret <a>), and a key pair out of that seed (<a_priv> and <a_pub>)
    unsigned char public_key[32], private_key[64];
    NSString *randomString = [self randomStringWithLength:32];
    self.authSecretData = [randomString dataUsingEncoding:NSUTF8StringEncoding];
    
    ed25519_create_keypair(public_key, private_key, self.authSecretData.bytes);
    self.authPrivateKeyData = [NSData dataWithBytes:private_key length:64];
    self.authPublicKeyData = [NSData dataWithBytes:public_key length:32];
    
    //Encrypt the public key using AES/GCM
    unsigned char encrypted[32];
    unsigned char tag[16];
    uint32_t len;
    len = encrypt_gcm(encrypted, tag, public_key, sizeof(public_key), aesKey, aesIV);
    if (len < 1) {
        return;
    }
    //Send the encrypted data and its signature
    NSData *epkData = [NSData dataWithBytes:encrypted length:len];
    NSData *authTagData = [NSData dataWithBytes:tag length:16];
    NSDictionary *plist = @{@"epk": epkData,
                            @"authTag": authTagData};
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:plist format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/x-apple-binary-plist" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)data.length] forKey:@"Content-Length"];
    [self post:@"/pair-setup-pin" body:data headers:headers];
}

- (void)doPairVerify1 {
    self.state = EPAirPlaySenderStateWaitingOnPairVerify1;
    
    //Generate a random 32 bytes number and use Curve25519 elliptic curve algorithm to build a verifier key pair <v_pub> and <v_priv> (32 bytes each)
    uint8_t privateKey[32];
    arc4random_buf(privateKey, 32);
    const uint8_t basepoint[32] = {9};
    unsigned char publicKey[32];
    curve25519_donna(publicKey, privateKey, basepoint);
    self.verifierPrivateKeyData = [NSData dataWithBytes:privateKey length:32];
    self.verifierPublicKeyData = [[NSData alloc] initWithBytes:publicKey length:32];
    
    if (self.authPrivateKeyData == nil) {
        //Retrieve the private <a_priv> and public key <a_pub> from the auth_secret <a> using Ed25519
        unsigned char public_key[32], private_key[64];
        ed25519_create_keypair(public_key, private_key, self.authSecretData.bytes);
        self.authPrivateKeyData = [NSData dataWithBytes:private_key length:64];
        self.authPublicKeyData = [NSData dataWithBytes:public_key length:32];
    }
    
    NSMutableData *data = [[NSMutableData alloc] init];
    char bytesToAppend[4] = {1, 0, 0, 0};
    [data appendBytes:bytesToAppend length:4];
    [data appendData:self.verifierPublicKeyData];
    [data appendData:self.authPublicKeyData];
    
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)data.length] forKey:@"Content-Length"];
    [self post:@"/pair-verify" body:data headers:headers];
}

- (void)doPairVerify2WithData:(NSData *)pairVerify1Response {
    self.state = EPAirPlaySenderStateWaitingOnPairVerify2;
    
    //The server public key <atv_pub>
    NSData *atvPublicKey = [pairVerify1Response subdataWithRange:NSMakeRange(0, 32)];
    
    //Create a shared secret between <v_priv> and <atv_pub> using Curve25519 algorithm
    uint8_t sharedSecret[32];
    curve25519_donna(sharedSecret, self.verifierPrivateKeyData.bytes, atvPublicKey.bytes);
    
    const void *verifyAesKey = "Pair-Verify-AES-Key";
    const void *verifyAesIV = "Pair-Verify-AES-IV";
    
    unsigned char hash[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512_CTX context;
    CC_SHA512_Init(&context);
    CC_SHA512_Update(&context, verifyAesKey, (CC_LONG)strlen(verifyAesKey));
    CC_SHA512_Update(&context, sharedSecret, 32);
    CC_SHA512_Final(hash, &context);
    
    unsigned char sharedSecretSha512AesKey[16];
    memcpy(sharedSecretSha512AesKey, hash, 16);
    
    CC_SHA512_Init(&context);
    CC_SHA512_Update(&context, verifyAesIV, (CC_LONG)strlen(verifyAesIV));
    CC_SHA512_Update(&context, sharedSecret, 32);
    CC_SHA512_Final(hash, &context);
    
    unsigned char sharedSecretSha512AesIV[16];
    memcpy(sharedSecretSha512AesIV, hash, 16);
    
    CCCryptorRef cryptor;
    CCCryptorStatus result = CCCryptorCreateWithMode(kCCEncrypt, kCCModeCTR, kCCAlgorithmAES128, ccNoPadding,
                                                     sharedSecretSha512AesIV,
                                                     sharedSecretSha512AesKey, 16, NULL, 0, 0, kCCModeOptionCTR_BE,
                                                     &cryptor); //OS X (10.7 or later)
    
    if (result != kCCSuccess) {
        NSLog(@"Failed to create cryptor: %d", result);
        return;
    }
    
    NSData *additionalData = [pairVerify1Response subdataWithRange:NSMakeRange(32, pairVerify1Response.length - 32)];
    size_t bufferLength = CCCryptorGetOutputLength(cryptor, additionalData.length, false);
    NSMutableData *buffer = [NSMutableData dataWithLength:bufferLength];
    size_t outLength;
    result = CCCryptorUpdate(cryptor, [additionalData bytes], [additionalData length],
                             [buffer mutableBytes], [buffer length], &outLength);
    if (result != kCCSuccess) {
        NSLog(@"Failed to encrypt: %d", result);
        CCCryptorRelease(cryptor);
        return;
    }
    
    //Sign the concatenation of <v_pub> and <atv_pub> using the keypair <a_pub> and <a_priv>
    NSMutableData *dataToSign = [NSMutableData dataWithData:self.verifierPublicKeyData];
    [dataToSign appendData:atvPublicKey];
    unsigned char signature[64];
    ed25519_sign(signature, dataToSign.bytes, dataToSign.length, self.authPublicKeyData.bytes, self.authPrivateKeyData.bytes);
    result = CCCryptorUpdate(cryptor, signature, 64, [buffer mutableBytes], [buffer length], &outLength);
    if (result != kCCSuccess) {
        NSLog(@"Failed to encrypt: %d", result);
        CCCryptorRelease(cryptor);
        return;
    }
    
    NSMutableData *data = [[NSMutableData alloc] init];
    char bytesToAppend[4] = {0, 0, 0, 0};
    [data appendBytes:bytesToAppend length:4];
    [data appendData:buffer];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)data.length] forKey:@"Content-Length"];
    [self post:@"/pair-verify" body:data headers:headers];
    CCCryptorRelease(cryptor);
}

- (void)pairingDidFinish {
    
}

#pragma mark -
#pragma mark Helpers

- (NSString *)randomStringWithLength:(int)len {
    NSString *letters = @"abcdef0123456789";
    NSMutableString *randomString = [NSMutableString stringWithCapacity: len];
    for (int i = 0; i < len; i++) {
        [randomString appendFormat:@"%C", [letters characterAtIndex:(NSUInteger)arc4random_uniform((uint32_t)[letters length])]];
    }
    
    return randomString;
}

- (void)printHTTPMessage:(CFHTTPMessageRef)message {
    BOOL isRequest = CFHTTPMessageIsRequest(message);
    NSMutableString *info = [[NSMutableString alloc] init];
    if (isRequest) {
        [info appendString:@"\n\nCLIENT -> SERVER:\n"];
        NSString *method = (__bridge_transfer NSString *)CFHTTPMessageCopyRequestMethod(message);
        NSString *url = (__bridge_transfer NSString *)CFHTTPMessageCopyRequestURL(message);
        [info appendFormat:@"%@ %@\n", method, url];
    } else {
        [info appendString:@"\n\nSERVER -> CLIENT:\n"];
        NSString *version = (__bridge_transfer NSString *)CFHTTPMessageCopyVersion(message);
        CFIndex statusCode = CFHTTPMessageGetResponseStatusCode(message);
        [info appendFormat:@"%@ %ld\n", version, statusCode];
    }
    NSDictionary *allHeaders = (__bridge_transfer NSDictionary *)CFHTTPMessageCopyAllHeaderFields(message);
    for (NSString *header in allHeaders) {
        [info appendFormat:@"%@: %@\n", header, [allHeaders objectForKey:header]];
    }
    NSLog(@"%@\n\n", info);
    NSData *bodyData = (__bridge_transfer NSData *)CFHTTPMessageCopyBody(message);
    if (bodyData.length > 0) {
        hexdump("\n\n", (void *)bodyData.bytes, (int)bodyData.length);
    }
}

#pragma mark -
#pragma mark Authenticated Encryption using GCM mode (AES/GCM)

static int encrypt_gcm(unsigned char *ciphertext, unsigned char *tag, unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    
    // 1. Create and initialise the context.
    // 2. Initialise the encryption operation.
    // 3. Set IV length if default 12 bytes (96 bits) is not appropriate.
    // 4. Initialise key and IV.
    if ( !(ctx = EVP_CIPHER_CTX_new()) ||
        (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) ||
        (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL) != 1) ||
        (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) )
    {
        printf("Error initialising AES 128 GCM encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
    {
        printf("Error encrypting\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    ciphertext_len = len;
    
    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
        printf("Error finalising encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    ciphertext_len += len;
    
    /*
     * This is goofy, but we need to invoke EVP_Cipher again to calculate the tag
     */
    EVP_Cipher(ctx, NULL, NULL, 0);
    
    /* Get the tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
    {
        printf("Error getting authtag\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

#pragma mark - AirPlay 2 Pairing

- (void)handlePairSetup:(NSString *)pin {
    if (pin == nil) {
#ifdef AIRPLAY_LOG
        NSLog(@"Pairing cancelled by user (pin is nil).");
#endif
        self.state = EPAirPlaySenderStateCancelled;
        return;
    }
    self.state = EPAirPlaySenderStateWaitingOnPairSetup1;
    
    NSString *clientId = @"Pair-Setup";
    const char *passwordChar = pin.UTF8String;
    size_t passwordLength = strlen(passwordChar);
    _user = srp_user_new(SRP_SHA512, SRP_NG_3072, clientId.UTF8String, (const unsigned char *)passwordChar, (int)passwordLength, 0, 0);
    
    char bytes[6] = {0x06, 0x01, 0x01, 0x00, 0x01, 0x00};
    NSData *data = [NSData dataWithBytes:bytes length:6];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)data.length] forKey:@"Content-Length"];
    [self post:@"/pair-setup" body:data headers:headers];
}

- (void)pair_setup:(NSData *)inData {
    NSArray<TLV8Item *> *items = [TLV8 decode:inData];
    TLV8Item *stateItem = [items itemWithTag:TLV8TagState];
    NSData *stateData = stateItem.value;
    int state = *(int *)([stateData bytes]);
    if (self.state == EPAirPlaySenderStateWaitingOnPairVerify1 || self.state == EPAirPlaySenderStateWaitingOnPairVerify2) {
        if (state == PairingStateM2) {
            [self pair_verify:items];
        } else if (state == PairingStateM4) {
            NSLog(@"Verification succeeded!");
        }
        return;
    }
    if (state == PairingStateM2) {
        [self pair_setup_m2_m3:items];
    } else if (state == PairingStateM4) {
        [self pair_setup_m4_m5:items];
    } else if (state == PairingStateM6) {
        [self pair_setup_m6:items];
    }
}

- (void)pair_setup_m2_m3:(NSArray<TLV8Item *> *)items {
    self.state = EPAirPlaySenderStateWaitingOnPairSetup2;
    
    NSData *salt = [items itemWithTag:TLV8TagSalt].value; //16 bytes
    NSData *pk = [items itemWithTag:TLV8TagPublicKey].value; //384 bytes
        
    // Calculate public client value and client evidence
    const char *auth_username = 0;
    const unsigned char *pkA;
    int pkA_len;
    const unsigned char *M1;
    int M1_len;
    
    // Calculate A
    srp_user_start_authentication(_user, &auth_username, &pkA, &pkA_len);
    
    // Calculate M1 (client proof)
    srp_user_process_challenge(_user, salt.bytes, (int)salt.length, pk.bytes, (int)pk.length, &M1, &M1_len);
    NSLog(@"A: %s (%d bytes)", pkA, pkA_len);
    NSLog(@"M1: %s (%d bytes)", M1, M1_len);
    
    char stateBytes[1] = {PairingStateM3};
    TLV8Item *stateItem = [[TLV8Item alloc] initWithTag:TLV8TagState value:[NSData dataWithBytes:stateBytes length:1]];
    TLV8Item *pkItem = [[TLV8Item alloc] initWithTag:TLV8TagPublicKey value:[NSData dataWithBytes:pkA length:pkA_len]];
    TLV8Item *proofItem = [[TLV8Item alloc] initWithTag:TLV8TagProof value:[NSData dataWithBytes:M1 length:M1_len]];
    
    NSArray *responseItems = @[stateItem, pkItem, proofItem];
    uint8_t *encodedRespBytes;
    int encLen = [TLV8 encode:responseItems toStream:&encodedRespBytes];
    
    NSData *responseData = [NSData dataWithBytes:encodedRespBytes length:encLen];
    
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%d", encLen] forKey:@"Content-Length"];
    [self post:@"/pair-setup" body:responseData headers:headers];
}

- (void)pair_setup_m4_m5:(NSArray<TLV8Item *> *)items {
    self.state = EPAirPlaySenderStateWaitingOnPairSetup3;
    
    NSData *proof = [items itemWithTag:TLV8TagProof].value; //64 bytes
    
    //TODO: check proof != nil
    
    // Check M2
    srp_user_verify_session(_user, proof.bytes);
    if (!srp_user_is_authenticated(_user)) {
        NSLog(@"AirPlay: Server authentication failed.");
        return;
    }
    
    int sessionKeyLen = 0;
    const unsigned char *sessionKey = srp_user_get_session_key(_user, &sessionKeyLen);
    if (!sessionKey) {
        NSLog(@"AirPlay: No valid session key.");
        return;
    }
    
    hexdump("Session key: ", (unsigned char *)sessionKey, 64);
    
    //Create a random seed (auth_secret <a>), and a key pair out of that seed (<a_priv> and <a_pub>)
    unsigned char public_key[32], private_key[64];
    NSString *randomString = [self randomStringWithLength:32];
    self.authSecretData = [randomString dataUsingEncoding:NSUTF8StringEncoding];
    
    ed25519_create_keypair(public_key, private_key, self.authSecretData.bytes);
    self.authPrivateKeyData = [NSData dataWithBytes:private_key length:64];
    self.authPublicKeyData = [NSData dataWithBytes:public_key length:32];
    
    int err;
    unsigned char prk[USHAMaxHashSize+1];
    uint8_t device_x[32];
    
    err = hkdfExtract(SHA512, (const unsigned char *)"Pair-Setup-Controller-Sign-Salt", 31, sessionKey, 64, prk);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExtract Error %d.\n", err);
    }
    hexdump("prk: ", prk, 256);
    
    err = hkdfExpand(SHA512, prk, USHAHashSize(SHA512), (const unsigned char *)"Pair-Setup-Controller-Sign-Info", 31, device_x, 32);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExpand Error %d.\n", err);
    }
    hexdump("device_x: ", device_x, 256);
    
    NSString *deviceID = @"C9635ED0964902E0";
    NSData *deviceIDData = [deviceID dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableData *device_info = [NSMutableData data];
    [device_info appendData:[NSData dataWithBytes:device_x length:32]];
    [device_info appendData:deviceIDData];
    [device_info appendData:self.authPublicKeyData];
    
    unsigned char signature[64];
    ed25519_sign(signature, device_info.bytes, device_info.length, self.authPublicKeyData.bytes, self.authPrivateKeyData.bytes);
    
    unsigned char prk2[USHAMaxHashSize+1];
    uint8_t session_key[32];
    
    err = hkdfExtract(SHA512, (const unsigned char *)"Pair-Setup-Encrypt-Salt", 23, sessionKey, 64, prk2);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExtract Error %d.\n", err);
    }
    hexdump("prk: ", prk2, 256);
    err = hkdfExpand(SHA512, prk2, USHAHashSize(SHA512), (const unsigned char *)"Pair-Setup-Encrypt-Info", 23, session_key, 32);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExpand Error %d.\n", err);
    }
    hexdump("session_key: ", session_key, 32);
    
    TLV8Item *identifierItem = [[TLV8Item alloc] initWithTag:TLV8TagIdentifier value:deviceIDData];
    TLV8Item *publicKeyItem = [[TLV8Item alloc] initWithTag:TLV8TagPublicKey value:self.authPublicKeyData];
    TLV8Item *signatureItem = [[TLV8Item alloc] initWithTag:TLV8TagSignature value:[NSData dataWithBytes:signature length:64]];
    
    NSArray *tlvItems = @[identifierItem, publicKeyItem, signatureItem];
    uint8_t *dec_tlv;
    int dec_tlv_len = [TLV8 encode:tlvItems toStream:&dec_tlv];
    
    hexdump("Plain Text: ", dec_tlv, dec_tlv_len);
    
//    unsigned char *nonce = "PS-Msg05";
    unsigned char nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x50, 0x53, 0x2D, 0x4D, 0x73, 0x67, 0x30, 0x35};
    
    unsigned char tag[16];
    unsigned char ct[118];
    
    struct chachapoly_ctx ctx;
    chachapoly_init(&ctx, session_key, 256);
    chachapoly_crypt(&ctx, nonce, NULL, 0, dec_tlv, dec_tlv_len, ct, tag, 16, 1);
    NSMutableData *encryptedData = [NSMutableData dataWithBytes:ct length:118];
    [encryptedData appendData:[NSData dataWithBytes:tag length:16]];
    
    char stateBytes[1] = {PairingStateM5};
    TLV8Item *stateItem = [[TLV8Item alloc] initWithTag:TLV8TagState value:[NSData dataWithBytes:stateBytes length:1]];
    TLV8Item *encryptedDataItem = [[TLV8Item alloc] initWithTag:TLV8TagEncryptedData value:encryptedData];
    
    NSArray *responseItems = @[stateItem, encryptedDataItem];
    uint8_t *encodedRespBytes;
    int encLen = [TLV8 encode:responseItems toStream:&encodedRespBytes];
    
    NSData *responseData = [NSData dataWithBytes:encodedRespBytes length:encLen];
    
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%d", encLen] forKey:@"Content-Length"];
    [self post:@"/pair-setup" body:responseData headers:headers];
}

- (void)pair_setup_m6:(NSArray<TLV8Item *> *)items {
    self.state = EPAirPlaySenderStateWaitingOnPairVerify1;
    
    NSData *encryptedData = [items itemWithTag:TLV8TagEncryptedData].value;
    NSData *encryptedTlvData = [encryptedData subdataWithRange:NSMakeRange(0, encryptedData.length - 16)]; //138 bytes
    NSData *tagData = [encryptedData subdataWithRange:NSMakeRange(encryptedData.length - 16, 16)]; //16 bytes
    
    int sessionKeyLen = 0;
    const unsigned char *sessionKey = srp_user_get_session_key(_user, &sessionKeyLen);
    if (!sessionKey) {
        NSLog(@"AirPlay: No valid session key.");
        return;
    }
    
    int err;
    unsigned char prk2[USHAMaxHashSize+1];
    uint8_t session_key[32];
    err = hkdfExtract(SHA512, (const unsigned char *)"Pair-Setup-Encrypt-Salt", 23, sessionKey, 64, prk2);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExtract Error %d.\n", err);
    }
    err = hkdfExpand(SHA512, prk2, USHAHashSize(SHA512), (const unsigned char *)"Pair-Setup-Encrypt-Info", 23, session_key, 32);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExpand Error %d.\n", err);
    }
    hexdump("session_key: ", session_key, 32);
    
    //decrypt
    unsigned char nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x50, 0x53, 0x2D, 0x4D, 0x73, 0x67, 0x30, 0x36};
    unsigned char dec_tlv[256];
    
    struct chachapoly_ctx ctx;
    chachapoly_init(&ctx, session_key, 256);
    chachapoly_crypt(&ctx, nonce, NULL, 0, (void *)encryptedTlvData.bytes, (int)encryptedTlvData.length, dec_tlv, (void *)tagData.bytes, 16, 0);
    
    NSArray<TLV8Item *> *accessoryItems = [TLV8 decode:[NSData dataWithBytes:dec_tlv length:encryptedTlvData.length]];
    TLV8Item *accessory_idItem = [accessoryItems itemWithTag:TLV8TagIdentifier];
    TLV8Item *accessory_ltpkItem = [accessoryItems itemWithTag:TLV8TagPublicKey];
    TLV8Item *accessory_sigItem = [accessoryItems itemWithTag:TLV8TagSignature];
    
    self.accessoryLtpk = accessory_ltpkItem.value;
    
    unsigned char prk[USHAMaxHashSize+1];
    uint8_t accessory_x[32];
    err = hkdfExtract(SHA512, (const unsigned char *)"Pair-Setup-Accessory-Sign-Salt", 30, sessionKey, 64, prk);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExtract Error %d.\n", err);
    }
    
    err = hkdfExpand(SHA512, prk, USHAHashSize(SHA512), (const unsigned char *)"Pair-Setup-Accessory-Sign-Info", 30, accessory_x, 32);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExpand Error %d.\n", err);
    }
    
    NSMutableData *accessory_info = [NSMutableData data];
    [accessory_info appendData:[NSData dataWithBytes:accessory_x length:32]];
    [accessory_info appendData:accessory_idItem.value];
    [accessory_info appendData:accessory_ltpkItem.value];
    
    //check signature
    if (!ed25519_verify(accessory_sigItem.value.bytes, accessory_info.bytes, accessory_info.length, self.accessoryLtpk.bytes)) {
        NSLog(@"Not verified!");
    } else {
        NSLog(@"Verified!");
    }
    
    
    //Generate a random 32 bytes number and use Curve25519 elliptic curve algorithm to build a verifier key pair <v_pub> and <v_priv> (32 bytes each)
    uint8_t privateKey[32];
    arc4random_buf(privateKey, 32);
    const uint8_t basepoint[32] = {9};
    unsigned char publicKey[32];
    curve25519_donna(publicKey, privateKey, basepoint);
    self.verifierPrivateKeyData = [NSData dataWithBytes:privateKey length:32];
    self.verifierPublicKeyData = [[NSData alloc] initWithBytes:publicKey length:32];
    
    if (self.authPrivateKeyData == nil) {
        //Retrieve the private <a_priv> and public key <a_pub> from the auth_secret <a> using Ed25519
        unsigned char public_key[32], private_key[64];
        ed25519_create_keypair(public_key, private_key, self.authSecretData.bytes);
        self.authPrivateKeyData = [NSData dataWithBytes:private_key length:64];
        self.authPublicKeyData = [NSData dataWithBytes:public_key length:32];
    }
    
    char stateBytes[1] = {PairingStateM1};
    TLV8Item *stateItem = [[TLV8Item alloc] initWithTag:TLV8TagState value:[NSData dataWithBytes:stateBytes length:1]];
    TLV8Item *pkItem = [[TLV8Item alloc] initWithTag:TLV8TagPublicKey value:self.verifierPublicKeyData];
    
    NSArray *responseItems = @[stateItem, pkItem];
    uint8_t *encodedRespBytes;
    int encLen = [TLV8 encode:responseItems toStream:&encodedRespBytes];
    
    NSData *responseData = [NSData dataWithBytes:encodedRespBytes length:encLen];
    
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%d", encLen] forKey:@"Content-Length"];
    [self post:@"/pair-verify" body:responseData headers:headers];
}

- (void)pair_verify:(NSArray<TLV8Item *> *)items {
    self.state = EPAirPlaySenderStateWaitingOnPairVerify2;
    
    self.accessory_curve_public = [items itemWithTag:TLV8TagPublicKey].value;
    NSData *encryptedData = [items itemWithTag:TLV8TagEncryptedData].value;
    NSData *encryptedTlvData = [encryptedData subdataWithRange:NSMakeRange(0, encryptedData.length - 16)];
    NSData *tagData = [encryptedData subdataWithRange:NSMakeRange(encryptedData.length - 16, 16)];
    
    uint8_t accessory_shared_key[32];
    curve25519_donna(accessory_shared_key, self.verifierPrivateKeyData.bytes, self.accessory_curve_public.bytes);
    self.accessory_shared_key = [NSData dataWithBytes:accessory_shared_key length:32];
    
    unsigned char prk[USHAMaxHashSize+1];
    uint8_t session_key[32];
    int err = hkdfExtract(SHA512, (const unsigned char *)"Pair-Verify-Encrypt-Salt", 24, accessory_shared_key, 32, prk);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExtract Error %d.\n", err);
    }
    err = hkdfExpand(SHA512, prk, USHAHashSize(SHA512), (const unsigned char *)"Pair-Verify-Encrypt-Info", 24, session_key, 32);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExpand Error %d.\n", err);
    }
    
    //decrypt ecrypted data
    unsigned char nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x50, 0x56, 0x2D, 0x4D, 0x73, 0x67, 0x30, 0x32}; //"PV-Msg02"
    unsigned char dec_tlv[256];
    struct chachapoly_ctx ctx;
    chachapoly_init(&ctx, session_key, 256);
    chachapoly_crypt(&ctx, nonce, NULL, 0, (void *)encryptedTlvData.bytes, (int)encryptedTlvData.length, dec_tlv, (void *)tagData.bytes, 16, 0);
    
    NSArray<TLV8Item *> *accessoryItems = [TLV8 decode:[NSData dataWithBytes:dec_tlv length:encryptedTlvData.length]];
    TLV8Item *accessory_idItem = [accessoryItems itemWithTag:TLV8TagIdentifier]; //36 bytes
    TLV8Item *accessory_sigItem = [accessoryItems itemWithTag:TLV8TagSignature];
   
    NSMutableData *accessory_info = [NSMutableData data];
    [accessory_info appendData:self.accessory_curve_public];
    [accessory_info appendData:accessory_idItem.value];
    [accessory_info appendData:self.verifierPublicKeyData];
    
    //check signature
    if (!ed25519_verify(accessory_sigItem.value.bytes, accessory_info.bytes, accessory_info.length, self.accessoryLtpk.bytes)) {
        NSLog(@"Not verified!");
    } else {
        NSLog(@"Verified!");
    }
    
    NSString *deviceID = @"C9635ED0964902E0";
    NSData *deviceIDData = [deviceID dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableData *device_info = [NSMutableData data];
    [device_info appendData:self.verifierPublicKeyData];
    [device_info appendData:deviceIDData];
    [device_info appendData:self.accessory_curve_public];
    
    unsigned char signature[64];
    ed25519_sign(signature, device_info.bytes, device_info.length, self.authPublicKeyData.bytes, self.authPrivateKeyData.bytes);
    
    unsigned char prk2[USHAMaxHashSize+1];
    uint8_t session_key2[32];
    
    err = hkdfExtract(SHA512, (const unsigned char *)"Pair-Verify-Encrypt-Salt", 24, self.accessory_shared_key.bytes, 32, prk2);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExtract Error %d.\n", err);
    }
    err = hkdfExpand(SHA512, prk2, USHAHashSize(SHA512), (const unsigned char *)"Pair-Verify-Encrypt-Info", 24, session_key2, 32);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExpand Error %d.\n", err);
    }
    
    TLV8Item *identifierItem = [[TLV8Item alloc] initWithTag:TLV8TagIdentifier value:deviceIDData];
    TLV8Item *signatureItem = [[TLV8Item alloc] initWithTag:TLV8TagSignature value:[NSData dataWithBytes:signature length:64]];

    NSArray *tlvItems = @[identifierItem, signatureItem];
    uint8_t *dec_tlv2;
    int dec_tlv_len = [TLV8 encode:tlvItems toStream:&dec_tlv2];
    
    //encrypt data
    unsigned char nonce2[12] = {0x00, 0x00, 0x00, 0x00, 0x50, 0x56, 0x2D, 0x4D, 0x73, 0x67, 0x30, 0x33}; //"PV-Msg03"
    unsigned char tag[16];
    unsigned char ct[256];

    struct chachapoly_ctx ctx2;
    chachapoly_init(&ctx2, session_key2, 256);
    chachapoly_crypt(&ctx2, nonce2, NULL, 0, dec_tlv2, dec_tlv_len, ct, tag, 16, 1);
    
    NSMutableData *encryptedData2 = [NSMutableData dataWithBytes:ct length:dec_tlv_len];
    [encryptedData2 appendData:[NSData dataWithBytes:tag length:16]];

    char stateBytes[1] = {PairingStateM3};
    TLV8Item *stateItem = [[TLV8Item alloc] initWithTag:TLV8TagState value:[NSData dataWithBytes:stateBytes length:1]];
    TLV8Item *encryptedDataItem = [[TLV8Item alloc] initWithTag:TLV8TagEncryptedData value:encryptedData2];

    NSArray *responseItems = @[stateItem, encryptedDataItem];
    uint8_t *encodedRespBytes;
    int encLen = [TLV8 encode:responseItems toStream:&encodedRespBytes];

    NSData *responseData = [NSData dataWithBytes:encodedRespBytes length:encLen];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%d", encLen] forKey:@"Content-Length"];
    [self post:@"/pair-verify" body:responseData headers:headers];
}

- (void)setCiphers {
    int err;
    unsigned char prk[USHAMaxHashSize+1];
    uint8_t outcoming_key[32];
    uint8_t incoming_key[32];
    err = hkdfExtract(SHA512, (const unsigned char *)"Control-Salt", 12, self.accessory_shared_key.bytes, 32, prk);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExtract Error %d.\n", err);
    }
    err = hkdfExpand(SHA512, prk, USHAHashSize(SHA512), (const unsigned char *)"Control-Write-Encryption-Key", 28, outcoming_key, 32);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExpand Error %d.\n", err);
    }
    self.outgoing_key = [NSData dataWithBytes:outcoming_key length:32];
    err = hkdfExpand(SHA512, prk, USHAHashSize(SHA512), (const unsigned char *)"Control-Read-Encryption-Key", 27, incoming_key, 32);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExpand Error %d.\n", err);
    }
    self.incoming_key = [NSData dataWithBytes:incoming_key length:32];
}

- (NSData *)encryptData:(NSData *)data {
    NSUInteger offset = 0;
    NSUInteger total = data.length;
    NSMutableData *mutableData = [NSMutableData data];
    while (offset < total) {
        NSUInteger length = MIN(total - offset, MAX_BLOCK_LENGTH);
        unsigned short *bytes = (unsigned short *)&length;
        NSData *lengthData = [NSData dataWithBytes:bytes length:sizeof(unsigned short)];
        NSData *blockData = [data subdataWithRange:NSMakeRange(offset, length)];
//            NSData *nonce = [[NSString stringWithFormat:@"00000000000%d", self.out_count] dataUsingEncoding:NSUTF8StringEncoding];//struct.pack("Q", self.out_count).rjust(12, b"\x00") Q - unsigned long long
//        unsigned char nonceBytes[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        unsigned long long c = (unsigned long long)self.in_count;
        unsigned long long *in_count_bytes = &c;
        char zeropadBytes[4] = {0x00, 0x00, 0x00, 0x00};
        NSMutableData *nonce = [NSMutableData dataWithBytes:zeropadBytes length:4];
        [nonce appendData:[NSData dataWithBytes:in_count_bytes length:8]];
        
        unsigned char tag[16];
        unsigned char ct[500];
        
        //out_cipher = ChaCha20_Poly1305.new(key=self.outgoing_key, nonce=nonce)
        //out_cipher.update(struct.pack("H", length))
        //enc, tag = out_cipher.encrypt_and_digest(block)
        struct chachapoly_ctx ctx;
        chachapoly_init(&ctx, self.outgoing_key.bytes, 256);
        chachapoly_crypt(&ctx, nonce.bytes, (void *)lengthData.bytes, (int)lengthData.length, (void *)blockData.bytes, (int)blockData.length, ct, tag, 16, 1);
        
        //ciphertext = length_bytes + enc + tag
        NSMutableData *ciphertext = [NSMutableData dataWithData:lengthData];
        [ciphertext appendData:[NSData dataWithBytes:ct length:blockData.length]];
        [ciphertext appendData:[NSData dataWithBytes:tag length:16]];

        offset += length;
        self.out_count += 1;
        [mutableData appendData:ciphertext];
    }
    return mutableData;
}

- (void)doPlay {
    
}

@end
