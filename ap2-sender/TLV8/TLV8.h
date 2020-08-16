//
//  TLV8.h
//  ap2-sender
//
//  Created by Viktoriia on 13.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "TLV8Item.h"

NS_ASSUME_NONNULL_BEGIN

@interface TLV8 : NSObject

+ (NSArray<TLV8Item *> *)decode:(NSData *)data;
+ (int)encode:(NSArray<TLV8Item *> *)items toBytes:(uint8_t *_Nonnull*_Nonnull)stream_ptr;

@end

NS_ASSUME_NONNULL_END
