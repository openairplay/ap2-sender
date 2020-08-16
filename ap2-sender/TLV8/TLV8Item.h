//
//  TLV8Item.h
//  ap2-sender
//
//  Created by Viktoriia on 13.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, PairingState) {
    PairingStateM1 = 0x01,
    PairingStateM2 = 0x02,
    PairingStateM3 = 0x03,
    PairingStateM4 = 0x04,
    PairingStateM5 = 0x05,
    PairingStateM6 = 0x06
};

typedef NS_ENUM(NSUInteger, TLV8Tag) {
    TLV8TagMethod = 0,
    TLV8TagIdentifier = 1,
    TLV8TagSalt = 2,
    TLV8TagPublicKey = 3,
    TLV8TagProof = 4,
    TLV8TagEncryptedData = 5,
    TLV8TagState = 6,
    TLV8TagError = 7,
    TLV8TagRetryDelay = 8,
    TLV8TagCertificate = 9,
    TLV8TagSignature = 10,
    TLV8TagPermissions = 11,
    TLV8TagFragmentData = 12,
    TLV8TagFragmentLast = 13,
    TLV8TagFlags = 19,
    TLV8TagSeparator = 255
};

@interface TLV8Item : NSObject

@property (assign) TLV8Tag  tag;
@property (strong) NSData   *value;

- (instancetype)initWithTag:(TLV8Tag)aTag value:(NSData *)aValue;

@end

NS_ASSUME_NONNULL_END
