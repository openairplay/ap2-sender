//
//  AirPlayServiceListener.h
//  ap2-sender
//
//  Created by Viktoriia on 14.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import <Foundation/Foundation.h>

@class AirPlayServiceListener;
@protocol AirPlayServiceListenerDelegate <NSObject>

- (void)airPlayServiceListenerFoundDevicesDidChange:(AirPlayServiceListener *)listener;

@end

@interface AirPlayServiceListener : NSObject

@property (strong, readonly)    NSMutableArray                      *foundDevices;
@property (weak)                id<AirPlayServiceListenerDelegate>  delegate;

- (void)startBrowsingForAirPlayServices;
- (void)stopBrowsingForAirPlayServices;

@end
