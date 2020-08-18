//
//  AirPlaySenderConnection.m
//  ap2-sender
//
//  Created by Viktoriia on 14.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import "AirPlaySenderConnection.h"
#import "TLV8.h"
#import "NSArray+TLV8Additions.h"

#import "srp.h"
#import "sha.h"
#import "ed25519.h"
#import "curve25519.h"
#import "chachapoly.h"

#define DEVICE_ID           @"C9635ED0964902E0"
#define TAG_LENGTH          16
#define MAX_BLOCK_LENGTH    0x400

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

/*!
 *  @typedef AirPlaySenderState
 *  @brief A list of possible states. */
typedef NS_ENUM(NSInteger, AirPlaySenderState) {
    AirPlaySenderStateNotConnected = 0,
    AirPlaySenderStateWaitingOnPairPinStart,
    AirPlaySenderStateWaitingOnPairSetup1,
    AirPlaySenderStateWaitingOnPairSetup2,
    AirPlaySenderStateWaitingOnPairSetup3,
    AirPlaySenderStateWaitingOnPairVerify1,
    AirPlaySenderStateWaitingOnPairVerify2,
    AirPlaySenderStateReadyToPlay,
    AirPlaySenderStateCancelled,
    AirPlaySenderStatePairingFailed
};

@interface AirPlaySenderConnection () <NSStreamDelegate> {
    struct SRPUser *_user;
}

@property (assign)  AirPlaySenderState  state;
@property (strong)  NSString            *hostAddress;
@property (strong)  NSString            *hostName;
@property (assign)  int                 port;

@property (strong)  NSInputStream       *inputStream;
@property (strong)  NSOutputStream      *outputStream;
@property (strong)  NSMutableData       *inputBuffer;

@property (strong)  NSMutableArray      *dataWriteQueue;
@property (assign)  int                 currentDataOffset;
@property (assign)  BOOL                canSendDirectly;


@property (strong)  NSData              *authSecretData;
@property (strong)  NSData              *authPrivateKeyData;
@property (strong)  NSData              *authPublicKeyData;

@property (strong)  NSData              *verifierPrivateKeyData;
@property (strong)  NSData              *verifierPublicKeyData;

@property (strong)  NSData              *accessoryLtpk;
@property (strong)  NSData              *accessoryCurvePublic;
@property (strong)  NSData              *accessorySharedKey;

@property (assign, getter=isEncrypted)  BOOL    encrypted;
@property (strong)                      NSData  *outgoingKey;
@property (strong)                      NSData  *incomingKey;
@property (assign)                      int     outCount;
@property (assign)                      int     inCount;

@end

@implementation AirPlaySenderConnection

- (id)initWithHostAddress:(NSString *)address name:(NSString *)name port:(int)port {
    self = [super init];
    if (self) {
        _hostAddress = address;
        _hostName = name;
        _port = port;
        
        _dataWriteQueue = [[NSMutableArray alloc] init];
        _currentDataOffset = 0;
        _canSendDirectly = NO;
        
        _state = AirPlaySenderStateNotConnected;
        
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
        _outCount = 0;
        _inCount = 0;
    }
    return self;
}

#pragma mark - Setup/Close

- (void)setup {
    if (self.dataWriteQueue && self.dataWriteQueue.count > 0) {
        [self.dataWriteQueue removeAllObjects];
        self.currentDataOffset = 0;
    }
    self.canSendDirectly = NO;
    self.state = AirPlaySenderStateNotConnected;
    
    //Creates readable and writable streams connected to a socket.
    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;
    CFStringRef hostname = NULL;
    if (!_hostName) {
        NSURL *serverURL = [NSURL URLWithString:[NSString stringWithFormat:@"http://%@", _hostAddress]];
        hostname = (__bridge CFStringRef)[serverURL host];
    } else {
        hostname =  (__bridge CFStringRef)_hostName;
    }
    CFStreamCreatePairWithSocketToHost(kCFAllocatorDefault, hostname, _port, &readStream, &writeStream);
    NSLog(@"Connecting to %@ (%@) at port %d...", _hostName, _hostAddress, _port);
    
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
            NSLog(@"The open has completed successfully.");
            break;
        case NSStreamEventHasSpaceAvailable:
//            NSLog(@"The stream can accept bytes for writing.");
            [self _sendData];
            break;
        case NSStreamEventHasBytesAvailable:;
//            NSLog(@"The stream has bytes to be read.");
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
            NSLog(@"An error %ld has occurred on the stream: %@.", (long)streamError.code, streamError.description);
            break;
        }
        case NSStreamEventEndEncountered:
        {
            NSLog(@"The end of the stream has been reached.");
            break;
        }
        default:
            break;
    }
}

#pragma mark - Processing Incoming Bytes

// YES return means that a complete request was parsed, and the caller
// should call again as the buffered bytes may have another complete
// request available.
- (BOOL)processIncomingBytes {
    if (_inputBuffer.length == 0) {
        return NO;
    }
    
    if (self.isEncrypted) {
        return [self processEncryptedIncomingBytes];
    }
    
    CFHTTPMessageRef message = CFHTTPMessageCreateEmpty(kCFAllocatorDefault, false);
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
    
    [self printHTTPMessage:message];
    
    long responseStatusCode = CFHTTPMessageGetResponseStatusCode(message);
            
    if (responseStatusCode == 200 && self.state != AirPlaySenderStateReadyToPlay) {
        if (self.state == AirPlaySenderStateWaitingOnPairPinStart) {
            //Request a pin.
            NSString *pin = nil;
            if (self.delegate && [self.delegate respondsToSelector:@selector(promptUserForPin)]) {
                pin = [self.delegate promptUserForPin];
            }
            [self pairSetupWithPin:pin];
            CFRelease(message);
            return YES;
        }
        
        if (self.state == AirPlaySenderStateWaitingOnPairVerify2) {
            NSLog(@"Verification complete!");
            self.encrypted = YES;
            [self setCiphers];
            
            self.state = AirPlaySenderStateReadyToPlay;
            [self pairingDidFinish];
            CFRelease(message);
            return YES;
        }
        
        //Gets the body from a CFHTTPMessage object.
        NSString *contentLengthValue = (__bridge_transfer NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Length");
        unsigned contentLength = contentLengthValue ? [contentLengthValue intValue] : 0;
        if (contentLength != 0) {
//            NSString *contentTypeValue = (__bridge_transfer NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Type");
//            if ([contentTypeValue isEqualToString:@"application/octet-stream"]) {
                NSData *requestBody = (__bridge_transfer NSData *)CFHTTPMessageCopyBody(message);
                [self continuePairSetupWithData:requestBody];
//            }
        }
        
        CFRelease(message);
        return YES;
    }
    
    [self handleMessage:message];
    CFRelease(message);
    
    return YES;
}

- (BOOL)processEncryptedIncomingBytes {
    //after successful pairing the connection switches to being encrypted using the format N:n_bytes:tag
    //where N is a 16 bit Little Endian length that describes the number of bytes in n_bytes and
    //n_bytes is encrypted using ChaCha20-Poly1305 with tag being the Poly1305 tag.
    unsigned short N = 0;
    [_inputBuffer getBytes:&N length:2];
    if (N > 0) {
        unsigned long long c = (unsigned long long)self.inCount;
        unsigned long long *in_count_bytes = &c;
        char zeroBytes[4] = {0x00, 0x00, 0x00, 0x00};
        NSMutableData *nonce = [NSMutableData dataWithBytes:zeroBytes length:4];
        [nonce appendData:[NSData dataWithBytes:in_count_bytes length:8]];
        
        unsigned short *bytes = (unsigned short *)&N;
        NSData *lengthData = [NSData dataWithBytes:bytes length:2];
        NSData *blockData = [_inputBuffer subdataWithRange:NSMakeRange(2, N)];
        NSData *tagData = [_inputBuffer subdataWithRange:NSMakeRange(N+2, TAG_LENGTH)];
        
        //decrypt data
        int blockDataLen = (int)blockData.length;
        unsigned char *dec_bytes = (unsigned char *)malloc(sizeof(unsigned char) * blockDataLen);
        struct chachapoly_ctx ctx;
        chachapoly_init(&ctx, self.incomingKey.bytes, 256);
        if (chachapoly_crypt(&ctx, nonce.bytes, lengthData.bytes, (int)lengthData.length, (void *)blockData.bytes, blockDataLen, dec_bytes, (void *)tagData.bytes, TAG_LENGTH, 0) == 0) {
            if (strncmp((const char *)dec_bytes, "RTSP", 4) == 0) {
                memcpy(dec_bytes, "HTTP", 4);
            }
            CFHTTPMessageRef message = CFHTTPMessageCreateEmpty(kCFAllocatorDefault, false);
            CFHTTPMessageAppendBytes(message, dec_bytes, N);
            
            if (CFHTTPMessageIsHeaderComplete(message)) {
                self.inCount++;
                
                NSString *contentLengthValue = (__bridge_transfer NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Length");
                unsigned contentLength = contentLengthValue ? [contentLengthValue intValue] : 0;
                NSData *body = (__bridge_transfer NSData *)CFHTTPMessageCopyBody(message);
                NSUInteger bodyLength = body.length;
                if (contentLength <= bodyLength) {
                    NSData *newBody = [NSData dataWithBytes:[body bytes] length:contentLength];
                    [_inputBuffer setLength:0];
                    [_inputBuffer appendBytes:([body bytes] + contentLength) length:(bodyLength - contentLength)];
                    CFHTTPMessageSetBody(message, (__bridge CFDataRef)newBody);
                } else {
                    CFRelease(message);
                    return NO;
                }
                
                [self printHTTPMessage:message];
                [self handleMessage:message];
                return YES;
            } else {
                CFRelease(message);
                return NO;
            }
        }
        free(dec_bytes);
    }
    return NO;
}

#pragma mark - Handlers

- (void)handleMessage:(CFHTTPMessageRef)message {
    //Gets the body from a CFHTTPMessage object.
    NSString *contentLengthValue = (__bridge_transfer NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Length");
    unsigned contentLength = contentLengthValue ? [contentLengthValue intValue] : 0;
    if (contentLength != 0) {
        NSString *contentTypeValue = (__bridge_transfer NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Type");
        if ([contentTypeValue isEqualToString:@"text/parameters"])
        {
            //TODO: parse data
//            NSData *requestBody = (__bridge_transfer NSData *)CFHTTPMessageCopyBody(message);
        }
        else if ([contentTypeValue isEqualToString:@"application/x-apple-binary-plist"])
        {
            NSData *requestBody = (__bridge_transfer NSData *)CFHTTPMessageCopyBody(message);
            NSPropertyListFormat format;
            NSError *error = nil;
            NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:requestBody options:NSPropertyListImmutable format:&format error:&error];
            if (plist == nil) {
                NSLog(@"Error parsing the property list: %@", error.debugDescription);
            } else {
                NSLog(@"Property list:\n%@", plist);
            }
        }
    }
}

- (void)pairingDidFailWithError:(NSString *)error {
    self.state = AirPlaySenderStatePairingFailed;
    NSLog(@"Pairing failed with error: %@", error);
}

- (void)pairingDidFinish {
    //POST /play
    //MP4 movies are supported using progressive download.
    //HTTP Live Streaming might be supported as well, as indicated by the VideoHTTPLiveStreams feature flag.
    //Start video playback. The body contains the following parameters:
    //  name                type        description
    //  -----------------------------------------------------------------
    //  Content-Location    URL         URL for the video
    //  Start-Position      float       starting position between 0 and 1
    //The relative starting position, a float value between 0 (beginning) and 1 (end) is used to start playing a video
    //at the exact same position as it was on the client.
//    NSDictionary *plist = @{@"Content-Location": @"http://commondatastorage.googleapis.com/gtv-videos-bucket/big_buck_bunny_1080p.mp4",
//                            @"Start-Position": @(0)};
//    NSData *bodyData = [NSPropertyListSerialization dataWithPropertyList:plist format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
//    NSString *contentType = @"application/x-apple-binary-plist";
//    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:3];
//    [headers setObject:contentType forKey:@"Content-Type"];
//    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)bodyData.length] forKey:@"Content-Length"];
//    [self post:@"/play" body:bodyData headers:headers];
    
    
    NSDictionary *plist = @{@"sessionUUID": @"b0feaa9c-dd30-11ea-abc1-f01898eb44de",
                            @"timingProtocol": @"None"};
    NSData *bodyData = [NSPropertyListSerialization dataWithPropertyList:plist format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    NSUInteger length = bodyData.length;
    NSString *setupRequest = [NSString stringWithFormat:
                              @"SETUP /2182745467221657149 RTSP/1.0\r\n"
                              "Content-Length: %lu\r\n"
                              "Content-Type: application/x-apple-binary-plist\r\n"
                              "User-Agent: AirPlay/381.13\r\n"
                              "X-Apple-HKP: 3\r\n"
                              "X-Apple-StreamID: 1\r\n"
                              "\r\n", (unsigned long)length];
    NSMutableData *requestData = [NSMutableData dataWithData:[setupRequest dataUsingEncoding:NSUTF8StringEncoding]];
    [requestData appendData:bodyData];
    [self sendData:requestData];
}

#pragma mark - POST/GET

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
    CFHTTPMessageSetHeaderFieldValue(request, (CFStringRef)@"User-Agent", (CFStringRef)@"AirPlay/381.13");
    CFHTTPMessageSetHeaderFieldValue(request, (CFStringRef)@"X-Apple-HKP", (CFStringRef)@"3"); //REQUIRED!
    
    //optional headers
    if (requestHeaders != nil) {
        for (NSString *headerName in requestHeaders) {
            CFHTTPMessageSetHeaderFieldValue(request, (__bridge CFStringRef)headerName, (__bridge CFStringRef)[requestHeaders objectForKey:headerName]);
        }
    }
    
    [self printHTTPMessage:request];
    
    //Serializes a CFHTTPMessage object
    NSData *serializedMsg = (__bridge_transfer NSData *)CFHTTPMessageCopySerializedMessage(request);
    [self sendData:serializedMsg];
}

#pragma mark - Sending Data

// Public interface for sending data.
- (void)sendData:(NSData *)data {
    if (!self.isEncrypted) {
        [self.dataWriteQueue insertObject:data atIndex:0];
    } else {
        //Encrypt and send the given data
        NSData *encryptedData = [self encryptData:data];
        [self.dataWriteQueue insertObject:encryptedData atIndex:0];
    }
    if (self.canSendDirectly) [self _sendData];
}

// Private
- (void)_sendData {
    self.canSendDirectly = NO;
    NSData *data = [self.dataWriteQueue lastObject];
    if (data == nil) {
        self.canSendDirectly = YES;
        return;
    }
    uint8_t *readBytes = (uint8_t *)[data bytes];
    readBytes += self.currentDataOffset;
    NSUInteger dataLength = [data length];
    NSUInteger lengthOfDataToWrite = (dataLength - self.currentDataOffset >= 1024) ? 1024 : (dataLength - self.currentDataOffset);
    NSInteger bytesWritten = [_outputStream write:readBytes maxLength:lengthOfDataToWrite];
    if (bytesWritten > 0) {
        self.currentDataOffset += (int)bytesWritten;
        if (self.currentDataOffset == dataLength) {
            [self.dataWriteQueue removeLastObject];
            self.currentDataOffset = 0;
        }
    }
}

#pragma mark - AirPlay 2 Pairing

- (void)startPairing {
    self.state = AirPlaySenderStateWaitingOnPairPinStart;
    [self post:@"/pair-pin-start"];
}

- (void)pairSetupWithPin:(NSString *)pin {
    if (pin == nil) {
        NSLog(@"Pairing cancelled by user (pin is nil).");
        self.state = AirPlaySenderStateCancelled;
        return;
    }
    
    self.state = AirPlaySenderStateWaitingOnPairSetup1;
    
    const char *passwordChar = pin.UTF8String;
    size_t passwordLength = strlen(passwordChar);
    const char *n_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
                        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
                        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
                        "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
                        "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
                        "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
                        "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
                        "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
                        "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
                        "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
                        "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
                        "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
    const char *g_hex = "5";
    _user = srp_user_new(SRP_SHA512, SRP_NG_CUSTOM, @"Pair-Setup".UTF8String, (const unsigned char *)passwordChar, (int)passwordLength, n_hex, g_hex);
    
    char stateBytes[] = {PairingStateM1};
    char pairingMethodBytes[] = {PairingMethodPairSetup};
    TLV8Item *stateItem = [[TLV8Item alloc] initWithTag:TLV8TagState value:[NSData dataWithBytes:stateBytes length:1]];
    TLV8Item *pairingMethodItem = [[TLV8Item alloc] initWithTag:TLV8TagMethod value:[NSData dataWithBytes:pairingMethodBytes length:1]];
    NSArray *tlvItems = @[stateItem, pairingMethodItem];
    uint8_t *encoded_tlv;
    int encoded_tlv_len = [TLV8 encode:tlvItems toBytes:&encoded_tlv];
    
    NSData *requestData = [NSData dataWithBytes:encoded_tlv length:encoded_tlv_len];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)requestData.length] forKey:@"Content-Length"];
    [self post:@"/pair-setup" body:requestData headers:headers];
    
    free(encoded_tlv);
}

- (void)continuePairSetupWithData:(NSData *)responseData {
    if (responseData.length == 0) {
        [self pairingDidFailWithError:@"server response data is empty"];
        return;
    }
    NSArray<TLV8Item *> *items = [TLV8 decode:responseData];
    TLV8Item *stateItem = [items itemWithTag:TLV8TagState];
    if (!stateItem) {
        [self pairingDidFailWithError:@"the State item is missing"];
        return;
    }
    NSData *stateData = stateItem.value;
    int state = *(int *)stateData.bytes;
    if (self.state == AirPlaySenderStateWaitingOnPairVerify1 || self.state == AirPlaySenderStateWaitingOnPairVerify2) {
        if (state == PairingStateM2) {
            [self pairVerify_m2:items];
        } else if (state == PairingStateM4) {
            NSLog(@"Verification succeeded!");
        }
        return;
    }
    if (state == PairingStateM2) {
        [self pairSetup_m2_m3:items];
    } else if (state == PairingStateM4) {
        [self pairSetup_m4_m5:items];
    } else if (state == PairingStateM6) {
        [self pairVerify_m1:items];
    }
}

- (void)pairSetup_m2_m3:(NSArray<TLV8Item *> *)items {
    self.state = AirPlaySenderStateWaitingOnPairSetup2;
    
    NSData *salt = [items itemWithTag:TLV8TagSalt].value;
    NSData *pk = [items itemWithTag:TLV8TagPublicKey].value;
    
    if (!salt || !pk) {
        [self pairingDidFailWithError:@"salt or pk is missing"];
        return;
    }
        
    // Calculate public client value and client evidence
    const char *auth_username = 0;
    const unsigned char *pkA = NULL;
    int pkA_len = 0;
    const unsigned char *M1 = NULL;
    int M1_len = 0;
    
    // Calculate A
    srp_user_start_authentication(_user, &auth_username, &pkA, &pkA_len);
    
    // Calculate M1 (client proof)
    srp_user_process_challenge(_user, salt.bytes, (int)salt.length, pk.bytes, (int)pk.length, &M1, &M1_len);
    
    char stateBytes[] = {PairingStateM3};
    TLV8Item *stateItem = [[TLV8Item alloc] initWithTag:TLV8TagState value:[NSData dataWithBytes:stateBytes length:1]];
    TLV8Item *pkItem = [[TLV8Item alloc] initWithTag:TLV8TagPublicKey value:[NSData dataWithBytes:pkA length:pkA_len]];
    TLV8Item *proofItem = [[TLV8Item alloc] initWithTag:TLV8TagProof value:[NSData dataWithBytes:M1 length:M1_len]];
    
    NSArray *tlvItems = @[stateItem, pkItem, proofItem];
    uint8_t *encoded_tlv;
    int encoded_tlv_len = [TLV8 encode:tlvItems toBytes:&encoded_tlv];
    
    NSData *responseData = [NSData dataWithBytes:encoded_tlv length:encoded_tlv_len];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%d", encoded_tlv_len] forKey:@"Content-Length"];
    [self post:@"/pair-setup" body:responseData headers:headers];
    
    free(encoded_tlv);
}

- (void)pairSetup_m4_m5:(NSArray<TLV8Item *> *)items {
    self.state = AirPlaySenderStateWaitingOnPairSetup3;
    
    NSData *proof = [items itemWithTag:TLV8TagProof].value; //64 bytes
    if (!proof) {
        [self pairingDidFailWithError:@"proof is missing"];
        return;
    }
    
    int sessionKeyLen = 0;
    const unsigned char *sessionKey = srp_user_get_session_key(_user, &sessionKeyLen);
    if (!sessionKey) {
        [self pairingDidFailWithError:@"no valid session key"];
        return;
    }
    hexdump("SRP Shared key:\n", (unsigned char *)sessionKey, 64);
    
    //in case the M1 step is done with the "Pair Setup with Auth" method,
    //during the M4 step of the pairing process, in addition to the PROOF TLV used in regular pair-setup,
    //the following TLV is added:
    //    TLV: 0x05,N,ENCRYPTED_DATA_WITH_TAG where N (int16) is the length of ENCRYPTED_DATA_WITH_TAG
    //see https://openairplay.github.io/airplay-spec/pairing/hkp.html#mfi-authentication
    TLV8Item *serverEncryptedDataItem = [items itemWithTag:TLV8TagEncryptedData];
    if (serverEncryptedDataItem) {
        NSData *serverEncryptedDataWithTag = serverEncryptedDataItem.value;
        if (serverEncryptedDataWithTag) {
            NSLog(@"Encrypted data is available (%lu bytes).", (unsigned long)serverEncryptedDataWithTag.length);
            
            unsigned char prk[USHAMaxHashSize+1];
            uint8_t session_key[32];
            int err = hkdfExtract(SHA512, (const unsigned char *)"Pair-Setup-Encrypt-Salt", 23, sessionKey, 64, prk);
            if (err != shaSuccess) {
                [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExtract Error %d.\n", err]];
                return;
            }
            err = hkdfExpand(SHA512, prk, USHAHashSize(SHA512), (const unsigned char *)"Pair-Setup-Encrypt-Info", 23, session_key, 32);
            if (err != shaSuccess) {
                [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExpand Error %d.\n", err]];
                return;
            }
            
            NSData *encryptedTlvData = [serverEncryptedDataWithTag subdataWithRange:NSMakeRange(0, serverEncryptedDataWithTag.length - TAG_LENGTH)];
            NSData *tagData = [serverEncryptedDataWithTag subdataWithRange:NSMakeRange(serverEncryptedDataWithTag.length - TAG_LENGTH, TAG_LENGTH)];
            const void *enc_tlv = encryptedTlvData.bytes;
            int enc_tlv_len = (int)encryptedTlvData.length;
            const void *tag = tagData.bytes;
            unsigned char *dec_tlv = (unsigned char *)malloc(sizeof(unsigned char) * enc_tlv_len);
            
            char zeroBytes[4] = {0x00, 0x00, 0x00, 0x00};
            NSMutableData *nonce = [[NSMutableData alloc] initWithBytes:zeroBytes length:4];
            [nonce appendData:[NSData dataWithBytes:"PS-Msg04" length:8]];
             
            struct chachapoly_ctx ctx;
            chachapoly_init(&ctx, session_key, 256);
            chachapoly_crypt(&ctx, nonce.bytes, NULL, 0, (void *)enc_tlv, enc_tlv_len, dec_tlv, (void *)tag, TAG_LENGTH, 0);
            
            //Decrypted data contains TLVs, which contain MFi Signature (signed by Apple authenticator IC) and used MFi certificate.
            NSArray<TLV8Item *> *tlvItems = [TLV8 decode:[NSData dataWithBytes:dec_tlv length:enc_tlv_len]];
            free(dec_tlv);
            TLV8Item *signatureItem = [tlvItems itemWithTag:TLV8TagSignature];
            TLV8Item *certificateItem = [tlvItems itemWithTag:TLV8TagCertificate];
            NSData *signatureData = signatureItem.value;
            NSData *certificateData = certificateItem.value;
            NSLog(@"Signature: %lu bytes, certificate: : %lu bytes", (unsigned long)signatureData.length, certificateData.length);
            
            //The message signed is a HKDF-SHA-512 key with the following parameters:
            //    InputKey = <SRP Shared key>
            //    Salt = ”MFi-Pair-Setup-Salt”
            //    Info = ”MFi-Pair-Setup-Info”
            //    OutputSize = 32 bytes
            unsigned char prk2[USHAMaxHashSize+1];
            uint8_t hkdf_key[32];
            err = hkdfExtract(SHA512, (const unsigned char *)"MFi-Pair-Setup-Salt", 19, sessionKey, 64, prk2);
            if (err != shaSuccess) {
                [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExtract Error %d.\n", err]];
                return;
            }
            err = hkdfExpand(SHA512, prk2, USHAHashSize(SHA512), (const unsigned char *)"MFi-Pair-Setup-Info", 19, hkdf_key, 32);
            if (err != shaSuccess) {
                [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExpand Error %d.\n", err]];
                return;
            }
            hexdump("Message to sign:\n", hkdf_key, 32);
            
            //TODO: sign the message using RSA-1024 with SHA-1 hash algorithm
        }
    }
    
    // Check M2
    srp_user_verify_session(_user, proof.bytes);
    if (!srp_user_is_authenticated(_user)) {
        [self pairingDidFailWithError:@"server authentication failed"];
        return;
    }
    
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
        [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExtract Error %d.\n", err]];
        return;
    }
    hexdump("prk:\n", prk, sizeof(prk));
    err = hkdfExpand(SHA512, prk, USHAHashSize(SHA512), (const unsigned char *)"Pair-Setup-Controller-Sign-Info", 31, device_x, 32);
    if (err != shaSuccess) {
        [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExpand Error %d.\n", err]];
        return;
    }
    hexdump("device_x:\n", device_x, sizeof(device_x));
    
    NSData *deviceID = [DEVICE_ID dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *deviceInfo = [NSMutableData data];
    [deviceInfo appendData:[NSData dataWithBytes:device_x length:32]];
    [deviceInfo appendData:deviceID];
    [deviceInfo appendData:self.authPublicKeyData];
    
    unsigned char signature[64];
    ed25519_sign(signature, deviceInfo.bytes, deviceInfo.length, self.authPublicKeyData.bytes, self.authPrivateKeyData.bytes);
    
    unsigned char prk2[USHAMaxHashSize+1];
    uint8_t session_key[32];
    err = hkdfExtract(SHA512, (const unsigned char *)"Pair-Setup-Encrypt-Salt", 23, sessionKey, 64, prk2);
    if (err != shaSuccess) {
        [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExtract Error %d.\n", err]];
        return;
    }
    hexdump("prk:\n", prk2, sizeof(prk2));
    err = hkdfExpand(SHA512, prk2, USHAHashSize(SHA512), (const unsigned char *)"Pair-Setup-Encrypt-Info", 23, session_key, 32);
    if (err != shaSuccess) {
        [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExpand Error %d.\n", err]];
        return;
    }
    hexdump("session_key:\n", session_key, 32);
    
    TLV8Item *identifierItem = [[TLV8Item alloc] initWithTag:TLV8TagIdentifier value:deviceID];
    TLV8Item *publicKeyItem = [[TLV8Item alloc] initWithTag:TLV8TagPublicKey value:self.authPublicKeyData];
    TLV8Item *signatureItem = [[TLV8Item alloc] initWithTag:TLV8TagSignature value:[NSData dataWithBytes:signature length:64]];
    
    NSArray *tlvItems = @[identifierItem, publicKeyItem, signatureItem];
    uint8_t *encoded_tlv;
    int encoded_tlv_len = [TLV8 encode:tlvItems toBytes:&encoded_tlv];
    
    unsigned char nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x50, 0x53, 0x2D, 0x4D, 0x73, 0x67, 0x30, 0x35}; //"PS-Msg05"
    unsigned char tag[TAG_LENGTH];
    unsigned char *encrypted_bytes = (unsigned char *)malloc(sizeof(unsigned char) * encoded_tlv_len);
    
    struct chachapoly_ctx ctx;
    chachapoly_init(&ctx, session_key, 256);
    chachapoly_crypt(&ctx, nonce, NULL, 0, encoded_tlv, encoded_tlv_len, encrypted_bytes, tag, TAG_LENGTH, 1);
    NSMutableData *encryptedData = [NSMutableData dataWithBytes:encrypted_bytes length:encoded_tlv_len];
    [encryptedData appendData:[NSData dataWithBytes:tag length:TAG_LENGTH]];
    
    char stateBytes[1] = {PairingStateM5};
    TLV8Item *stateItem = [[TLV8Item alloc] initWithTag:TLV8TagState value:[NSData dataWithBytes:stateBytes length:1]];
    TLV8Item *encryptedDataItem = [[TLV8Item alloc] initWithTag:TLV8TagEncryptedData value:encryptedData];
    
    NSArray *responseItems = @[stateItem, encryptedDataItem];
    uint8_t *encoded_bytes;
    int len = [TLV8 encode:responseItems toBytes:&encoded_bytes];
    
    NSData *responseData = [NSData dataWithBytes:encoded_bytes length:len];
    
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%d", len] forKey:@"Content-Length"];
    [self post:@"/pair-setup" body:responseData headers:headers];
    
    free(encrypted_bytes);
    free(encoded_tlv);
    free(encoded_bytes);
}

- (void)pairVerify_m1:(NSArray<TLV8Item *> *)items {
    self.state = AirPlaySenderStateWaitingOnPairVerify1;
    
    NSData *encryptedData = [items itemWithTag:TLV8TagEncryptedData].value;
    NSData *encryptedTlvData = [encryptedData subdataWithRange:NSMakeRange(0, encryptedData.length - TAG_LENGTH)];
    NSData *tagData = [encryptedData subdataWithRange:NSMakeRange(encryptedData.length - TAG_LENGTH, TAG_LENGTH)];
    
    int sessionKeyLen = 0;
    const unsigned char *sessionKey = srp_user_get_session_key(_user, &sessionKeyLen);
    if (!sessionKey) {
        [self pairingDidFailWithError:@"no valid session key"];
        return;
    }
    
    int err;
    unsigned char prk2[USHAMaxHashSize+1];
    uint8_t session_key[32];
    err = hkdfExtract(SHA512, (const unsigned char *)"Pair-Setup-Encrypt-Salt", 23, sessionKey, 64, prk2);
    if (err != shaSuccess) {
        [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExtract Error %d.\n", err]];
        return;
    }
    err = hkdfExpand(SHA512, prk2, USHAHashSize(SHA512), (const unsigned char *)"Pair-Setup-Encrypt-Info", 23, session_key, 32);
    if (err != shaSuccess) {
        [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExpand Error %d.\n", err]];
        return;
    }
    hexdump("session_key:\n", session_key, 32);
    
    //decrypt data
    unsigned char nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x50, 0x53, 0x2D, 0x4D, 0x73, 0x67, 0x30, 0x36}; //"PS-Msg06"
    const void *enc_tlv = encryptedTlvData.bytes;
    int enc_tlv_len = (int)encryptedTlvData.length;
    const void *tag = tagData.bytes;
    unsigned char *dec_tlv = (unsigned char *)malloc(sizeof(unsigned char) * enc_tlv_len);
    
    struct chachapoly_ctx ctx;
    chachapoly_init(&ctx, session_key, 256);
    chachapoly_crypt(&ctx, nonce, NULL, 0, (void *)enc_tlv, enc_tlv_len, dec_tlv, (void *)tag, TAG_LENGTH, 0);
    
    NSArray<TLV8Item *> *accessoryItems = [TLV8 decode:[NSData dataWithBytes:dec_tlv length:enc_tlv_len]];
    TLV8Item *accessory_idItem = [accessoryItems itemWithTag:TLV8TagIdentifier];
    TLV8Item *accessory_ltpkItem = [accessoryItems itemWithTag:TLV8TagPublicKey];
    TLV8Item *accessory_sigItem = [accessoryItems itemWithTag:TLV8TagSignature];
    
    free(dec_tlv);
    
    self.accessoryLtpk = accessory_ltpkItem.value;
    
    unsigned char prk[USHAMaxHashSize+1];
    uint8_t accessory_x[32];
    err = hkdfExtract(SHA512, (const unsigned char *)"Pair-Setup-Accessory-Sign-Salt", 30, sessionKey, 64, prk);
    if (err != shaSuccess) {
        [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExtract Error %d.\n", err]];
        return;
    }
    err = hkdfExpand(SHA512, prk, USHAHashSize(SHA512), (const unsigned char *)"Pair-Setup-Accessory-Sign-Info", 30, accessory_x, 32);
    if (err != shaSuccess) {
        [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExpand Error %d.\n", err]];
        return;
    }
    
    NSMutableData *accessoryInfo = [NSMutableData data];
    [accessoryInfo appendData:[NSData dataWithBytes:accessory_x length:32]];
    [accessoryInfo appendData:accessory_idItem.value];
    [accessoryInfo appendData:accessory_ltpkItem.value];
    
    //check the signature
    if (!ed25519_verify(accessory_sigItem.value.bytes, accessoryInfo.bytes, accessoryInfo.length, self.accessoryLtpk.bytes)) {
        [self pairingDidFailWithError:@"signature not verified!"];
        return;
    }
    
    NSLog(@"Signature is valid!");
    
    //Generate a random 32 bytes number and use Curve25519 elliptic curve algorithm to build a verifier key pair <v_pub> and <v_priv> (32 bytes each)
    uint8_t privateKey[32];
    arc4random_buf(privateKey, 32);
    const uint8_t basepoint[32] = {9};
    unsigned char publicKey[32];
    curve25519_donna(publicKey, privateKey, basepoint);
    self.verifierPrivateKeyData = [NSData dataWithBytes:privateKey length:32];
    self.verifierPublicKeyData = [[NSData alloc] initWithBytes:publicKey length:32];
    
    char stateBytes[] = {PairingStateM1};
    TLV8Item *stateItem = [[TLV8Item alloc] initWithTag:TLV8TagState value:[NSData dataWithBytes:stateBytes length:1]];
    TLV8Item *pkItem = [[TLV8Item alloc] initWithTag:TLV8TagPublicKey value:self.verifierPublicKeyData];
    
    NSArray *responseItems = @[stateItem, pkItem];
    uint8_t *encoded_bytes;
    int len = [TLV8 encode:responseItems toBytes:&encoded_bytes];
    
    NSData *responseData = [NSData dataWithBytes:encoded_bytes length:len];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%d", len] forKey:@"Content-Length"];
    [self post:@"/pair-verify" body:responseData headers:headers];
    
    free(encoded_bytes);
}

- (void)pairVerify_m2:(NSArray<TLV8Item *> *)items {
    self.state = AirPlaySenderStateWaitingOnPairVerify2;
    
    self.accessoryCurvePublic = [items itemWithTag:TLV8TagPublicKey].value;
    NSData *accessoryEncryptedDataWithTag = [items itemWithTag:TLV8TagEncryptedData].value;
    NSData *accessoryEncryptedTlvData = [accessoryEncryptedDataWithTag subdataWithRange:NSMakeRange(0, accessoryEncryptedDataWithTag.length - TAG_LENGTH)];
    NSData *accessoryTagData = [accessoryEncryptedDataWithTag subdataWithRange:NSMakeRange(accessoryEncryptedDataWithTag.length - TAG_LENGTH, TAG_LENGTH)];
    
    uint8_t accessory_shared_key[32];
    curve25519_donna(accessory_shared_key, self.verifierPrivateKeyData.bytes, self.accessoryCurvePublic.bytes);
    self.accessorySharedKey = [NSData dataWithBytes:accessory_shared_key length:32];
    
    unsigned char prk[USHAMaxHashSize+1];
    uint8_t session_key[32];
    int err = hkdfExtract(SHA512, (const unsigned char *)"Pair-Verify-Encrypt-Salt", 24, accessory_shared_key, 32, prk);
    if (err != shaSuccess) {
        [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExtract Error %d.\n", err]];
        return;
    }
    err = hkdfExpand(SHA512, prk, USHAHashSize(SHA512), (const unsigned char *)"Pair-Verify-Encrypt-Info", 24, session_key, 32);
    if (err != shaSuccess) {
        [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExpand Error %d.\n", err]];
        return;
    }
    
    //decrypt ecrypted data
    unsigned char nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x50, 0x56, 0x2D, 0x4D, 0x73, 0x67, 0x30, 0x32}; //"PV-Msg02"
    const void *enc_tlv = accessoryEncryptedTlvData.bytes;
    int enc_tlv_len = (int)accessoryEncryptedTlvData.length;
    unsigned char *dec_tlv = (unsigned char *)malloc(sizeof(unsigned char) * enc_tlv_len);
    struct chachapoly_ctx ctx;
    chachapoly_init(&ctx, session_key, 256);
    chachapoly_crypt(&ctx, nonce, NULL, 0, (void *)enc_tlv, enc_tlv_len, dec_tlv, (void *)accessoryTagData.bytes, TAG_LENGTH, 0);
    
    NSArray<TLV8Item *> *accessoryItems = [TLV8 decode:[NSData dataWithBytes:dec_tlv length:enc_tlv_len]];
    TLV8Item *accessoryIdentifierItem = [accessoryItems itemWithTag:TLV8TagIdentifier];
    TLV8Item *accessorySignatureItem = [accessoryItems itemWithTag:TLV8TagSignature];
    
    free(dec_tlv);
   
    NSMutableData *accessoryInfo = [NSMutableData data];
    [accessoryInfo appendData:self.accessoryCurvePublic];
    [accessoryInfo appendData:accessoryIdentifierItem.value];
    [accessoryInfo appendData:self.verifierPublicKeyData];
    
    //check the signature
    if (!ed25519_verify(accessorySignatureItem.value.bytes, accessoryInfo.bytes, accessoryInfo.length, self.accessoryLtpk.bytes)) {
        [self pairingDidFailWithError:@"signature not verified!"];
        return;
    }
    
    NSLog(@"Signature is valid!");
    
    NSData *deviceID = [DEVICE_ID dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableData *deviceInfo = [NSMutableData data];
    [deviceInfo appendData:self.verifierPublicKeyData];
    [deviceInfo appendData:deviceID];
    [deviceInfo appendData:self.accessoryCurvePublic];
    
    unsigned char signature[64];
    ed25519_sign(signature, deviceInfo.bytes, deviceInfo.length, self.authPublicKeyData.bytes, self.authPrivateKeyData.bytes);
    
    TLV8Item *identifierItem = [[TLV8Item alloc] initWithTag:TLV8TagIdentifier value:deviceID];
    TLV8Item *signatureItem = [[TLV8Item alloc] initWithTag:TLV8TagSignature value:[NSData dataWithBytes:signature length:64]];

    NSArray *tlvItems = @[identifierItem, signatureItem];
    uint8_t *encoded_tlv;
    int encoded_tlv_len = [TLV8 encode:tlvItems toBytes:&encoded_tlv];
    
    unsigned char prk2[USHAMaxHashSize+1];
    uint8_t session_key2[32];
    err = hkdfExtract(SHA512, (const unsigned char *)"Pair-Verify-Encrypt-Salt", 24, self.accessorySharedKey.bytes, 32, prk2);
    if (err != shaSuccess) {
        [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExtract Error %d.\n", err]];
        return;
    }
    err = hkdfExpand(SHA512, prk2, USHAHashSize(SHA512), (const unsigned char *)"Pair-Verify-Encrypt-Info", 24, session_key2, 32);
    if (err != shaSuccess) {
        [self pairingDidFailWithError:[NSString stringWithFormat:@"hashHkdf(): hkdfExpand Error %d.\n", err]];
        return;
    }
    
    //encrypt data
    unsigned char nonce2[12] = {0x00, 0x00, 0x00, 0x00, 0x50, 0x56, 0x2D, 0x4D, 0x73, 0x67, 0x30, 0x33}; //"PV-Msg03"
    unsigned char tag[TAG_LENGTH];
    unsigned char *encrypted_tlv = (unsigned char *)malloc(sizeof(unsigned char) * encoded_tlv_len);

    struct chachapoly_ctx ctx2;
    chachapoly_init(&ctx2, session_key2, 256);
    chachapoly_crypt(&ctx2, nonce2, NULL, 0, encoded_tlv, encoded_tlv_len, encrypted_tlv, tag, TAG_LENGTH, 1);
    
    NSMutableData *encryptedData = [NSMutableData dataWithBytes:encrypted_tlv length:encoded_tlv_len];
    [encryptedData appendData:[NSData dataWithBytes:tag length:TAG_LENGTH]];

    char stateBytes[1] = {PairingStateM3};
    TLV8Item *stateItem = [[TLV8Item alloc] initWithTag:TLV8TagState value:[NSData dataWithBytes:stateBytes length:1]];
    TLV8Item *encryptedDataItem = [[TLV8Item alloc] initWithTag:TLV8TagEncryptedData value:encryptedData];

    NSArray *responseItems = @[stateItem, encryptedDataItem];
    uint8_t *encoded_bytes;
    int len = [TLV8 encode:responseItems toBytes:&encoded_bytes];

    NSData *responseData = [NSData dataWithBytes:encoded_bytes length:len];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%d", len] forKey:@"Content-Length"];
    [self post:@"/pair-verify" body:responseData headers:headers];
    
    free(encrypted_tlv);
    free(encoded_tlv);
    free(encoded_bytes);
}

#pragma mark - Encryption

- (void)setCiphers {
    int err;
    unsigned char prk[USHAMaxHashSize+1];
    uint8_t outcoming_key[32];
    uint8_t incoming_key[32];
    err = hkdfExtract(SHA512, (const unsigned char *)"Control-Salt", 12, self.accessorySharedKey.bytes, 32, prk);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExtract Error %d.\n", err);
        return;
    }
    err = hkdfExpand(SHA512, prk, USHAHashSize(SHA512), (const unsigned char *)"Control-Write-Encryption-Key", 28, outcoming_key, 32);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExpand Error %d.\n", err);
        return;
    }
    self.outgoingKey = [NSData dataWithBytes:outcoming_key length:32];
    err = hkdfExpand(SHA512, prk, USHAHashSize(SHA512), (const unsigned char *)"Control-Read-Encryption-Key", 27, incoming_key, 32);
    if (err != shaSuccess) {
        fprintf(stderr, "hashHkdf(): hkdfExpand Error %d.\n", err);
        return;
    }
    self.incomingKey = [NSData dataWithBytes:incoming_key length:32];
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
        unsigned long long c = (unsigned long long)self.outCount;
        unsigned long long *out_count_bytes = &c;
        char zeroBytes[4] = {0x00, 0x00, 0x00, 0x00};
        NSMutableData *nonce = [NSMutableData dataWithBytes:zeroBytes length:4];
        [nonce appendData:[NSData dataWithBytes:out_count_bytes length:8]];
        
        unsigned char tag[TAG_LENGTH];
        int len = (int)blockData.length;
        unsigned char *ct = (unsigned char *)malloc(sizeof(unsigned char) * len);
        struct chachapoly_ctx ctx;
        chachapoly_init(&ctx, self.outgoingKey.bytes, 256);
        chachapoly_crypt(&ctx, nonce.bytes, (void *)lengthData.bytes, (int)lengthData.length, (void *)blockData.bytes, len, ct, tag, TAG_LENGTH, 1);
        
        NSMutableData *ciphertext = [NSMutableData dataWithData:lengthData];
        [ciphertext appendData:[NSData dataWithBytes:ct length:blockData.length]];
        [ciphertext appendData:[NSData dataWithBytes:tag length:TAG_LENGTH]];
        
        free(ct);

        offset += length;
        self.outCount += 1;
        [mutableData appendData:ciphertext];
    }
    return mutableData;
}

#pragma mark - Helpers

- (NSString *)randomStringWithLength:(int)len {
    NSString *letters = @"abcdef0123456789";
    NSMutableString *randomString = [NSMutableString stringWithCapacity:len];
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

@end
