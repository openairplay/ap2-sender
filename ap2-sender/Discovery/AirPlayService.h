//
//  AirPlayService.h
//  ap2-sender
//
//  Created by Viktoriia on 14.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AirPlayService : NSObject

@property (strong) NSNetService     *netService;
@property (strong) NSString         *name;
@property (strong) NSMutableArray   *ipAddresses;
@property (strong) NSString         *macAddress;
@property (strong) NSString         *serverVersion;
@property (strong) NSString         *model;
@property (assign) unsigned long    features;
@property (assign, getter=isPasswordProtected) BOOL passwordProtected;
@property (assign, getter=isPasscodeProtected) BOOL passcodeProtected;
@property (assign, getter=isDeviceVerificationEnabled) BOOL deviceVerificationEnabled;
@property (assign) int              protocolVersion;

- (id)initWithNetService:(NSNetService *)service;

- (NSString *)primaryIPv4Address;

- (BOOL)isVideoSupported;
- (BOOL)isPhotoSupported;
- (BOOL)isVideoFairPlaySupported;
- (BOOL)isVideoVolumeControlSupported;
- (BOOL)isVideoHLSSupported;
- (BOOL)isSlideshowSupported;
- (BOOL)isScreenMirroringSupported;
- (BOOL)isScreenRotationSupported;
- (BOOL)isAudioSupported;
- (BOOL)isAudioPacketRedundancySupported;
- (BOOL)isFairPlaySecureAuthSupported;
- (BOOL)isPhotoCachingSupported;

- (NSString *)description;

@end
