//
//  AirPlayService.m
//  ap2-sender
//
//  Created by Viktoriia on 14.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import "AirPlayService.h"

@implementation AirPlayService

- (id)initWithNetService:(NSNetService *)service {
    self = [super init];
    if (self) {
        _netService = service;
        _name = nil;
        _macAddress = nil;
        _ipAddresses = [[NSMutableArray alloc] init];
        _serverVersion = nil;
        _model = nil;
        _features = 0;
        _passwordProtected = NO;
        _passcodeProtected = NO;
        _deviceVerificationEnabled = NO;
        _protocolVersion = 1;
    }
    return self;
}

#pragma mark - Getting Addresses

- (NSString *)primaryIPv4Address {
    NSString *host = nil;
    for (NSDictionary *addrInfo in self.ipAddresses) {
        if ([[addrInfo objectForKey:@"type"] isEqualToString:@"ipv4"]) {
            host = [addrInfo objectForKey:@"address"];
            break;
        }
    }
    return host;
}

#pragma mark - Features

- (BOOL)isVideoSupported {
    return (0 < (self.features & (1 << 0)));
}

- (BOOL)isPhotoSupported {
    return (0 < (self.features & (1 << 1)));
}

- (BOOL)isVideoFairPlaySupported {
    return (0 < (self.features & (1 << 2)));
}

- (BOOL)isVideoVolumeControlSupported {
    return (0 < (self.features & (1 << 3)));
}

- (BOOL)isVideoHLSSupported {
    return (0 < (self.features & (1 << 4)));
}

- (BOOL)isSlideshowSupported {
    return (0 < (self.features & (1 << 5)));
}

- (BOOL)isScreenMirroringSupported {
    return (0 < (self.features & (1 << 7)));
}

- (BOOL)isScreenRotationSupported {
    return (0 < (self.features & (1 << 8)));
}

- (BOOL)isAudioSupported {
    return (0 < (self.features & (1 << 9)));
}

- (BOOL)isAudioPacketRedundancySupported {
    return (0 < (self.features & (1 << 11)));
}

- (BOOL)isFairPlaySecureAuthSupported {
    return (0 < (self.features & (1 << 12)));
}

- (BOOL)isPhotoCachingSupported {
    return (0 < (self.features & (1 << 13)));
}

- (BOOL)supportsCoreUtilsPairingAndEncryption {
    return (0 < (self.features & ((unsigned long)1 << 38)));
}

- (BOOL)supportsHKPairingAndAccessControl {
    return (0 < (self.features & ((unsigned long)1 << 46)));
}

- (BOOL)supportsUnifiedPairSetupAndMFi {
    return (0 < (self.features & ((unsigned long)1 << 51)));
}

- (BOOL)supportsMFiAuthentication {
    return (0 < (self.features & ((unsigned long)1 << 26)));
}

- (BOOL)supportsFairPlayAuthentication {
    return (0 < (self.features & ((unsigned long)1 << 14)));
}

- (NSString *)description {
    NSString *addr = @"";
    for (NSDictionary *addrInfo in self.ipAddresses) {
        addr = [addr stringByAppendingFormat:@"\t\t%@:%@\n", [addrInfo objectForKey:@"address"],
                [addrInfo objectForKey:@"port"]];
    }
    NSString *featuresString = [NSString stringWithFormat:@"0x%lX", (self.features & 0xffffffff)];;
    if ((self.features >> 32 & 0xffffffff) != 0) {
        featuresString = [featuresString stringByAppendingFormat:@",0x%lX", (self.features >> 32 & 0xffffffff)];
    }
    return [NSString stringWithFormat:@"%@:\n\t"
            "MAC address: %@\n\t"
            "model: %@\n\t"
            "server version: %@\n\t"
            "host name: %@\n\t"
            "IP addresses:\n%@\t"
            "Features: %@\n\t\t"
            "Video: %d\n\t\t"
            "Photo: %d\n\t\t"
            "VideoFairPlay: %d\n\t\t"
            "VideoVolumeControl: %d\n\t\t"
            "VideoHTTPLiveStreams: %d\n\t\t"
            "Slideshow: %d\n\t\t"
            "Screen: %d\n\t\t"
            "ScreenRotate: %d\n\t\t"
            "Audio: %d\n\t\t"
            "AudioRedundant: %d\n\t\t"
            "FPSAPv2pt5_AES_GCM: %d\n\t\t"
            "PhotoCaching: %d\n\t\t"
            "SupportsHKPairingAndAccessControl: %d\n\t\t"
            "SupportsUnifiedPairSetupAndMFi: %d\n\t\t"
            "MFi auth: %d\n\t\t"
            "FairPlay auth: %d\n\t"
            "Password protected: %d\n\t"
            "Passcode protected: %d\n\t"
            "Device verification enabled: %d\n\t"
            "Protocol version: %d\n",
            self.name,
            self.macAddress,
            self.model,
            self.serverVersion,
            self.netService.hostName,
            addr,
            featuresString,
            [self isVideoSupported],
            [self isPhotoSupported],
            [self isVideoFairPlaySupported],
            [self isVideoVolumeControlSupported],
            [self isVideoHLSSupported],
            [self isSlideshowSupported],
            [self isScreenMirroringSupported],
            [self isScreenRotationSupported],
            [self isAudioSupported],
            [self isAudioPacketRedundancySupported],
            [self isFairPlaySecureAuthSupported],
            [self isPhotoCachingSupported],
            [self supportsHKPairingAndAccessControl],
            [self supportsUnifiedPairSetupAndMFi],
            [self supportsMFiAuthentication],
            [self supportsFairPlayAuthentication],
            [self isPasswordProtected],
            [self isPasscodeProtected],
            self.isDeviceVerificationEnabled,
            self.protocolVersion];
}

@end
