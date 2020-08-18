//
//  AirPlaySenderConnection.h
//  ap2-sender
//
//  Created by Viktoriia on 14.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, PairingState) {
    PairingStateM1 = 0x01,
    PairingStateM2 = 0x02,
    PairingStateM3 = 0x03,
    PairingStateM4 = 0x04,
    PairingStateM5 = 0x05,
    PairingStateM6 = 0x06
};

typedef NS_ENUM(NSUInteger, PairingMethod) {
    PairingMethodPairSetup          = 0x00,
    PairingMethodPairSetupWithAuth  = 0x01,
    PairingMethodPairVerify         = 0x02,
    PairingMethodAddPairing         = 0x03,
    PairingMethodRemovePairing      = 0x04,
    PairingMethodListPairings       = 0x05
};

@protocol AirPlaySenderConnectionDelegate <NSObject>

- (NSString *)promptUserForPin;

@end

@interface AirPlaySenderConnection : NSObject

@property (weak) id<AirPlaySenderConnectionDelegate> delegate;

- (id)initWithHostAddress:(NSString *)address name:(NSString *)name port:(int)port;

- (void)setup;
- (void)close;

- (void)startPairing;

@end
