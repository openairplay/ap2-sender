//
//  AirPlaySenderConnection.h
//  ap2-sender
//
//  Created by Viktoriia on 14.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import <Foundation/Foundation.h>

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
