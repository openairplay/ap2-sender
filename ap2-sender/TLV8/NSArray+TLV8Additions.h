//
//  NSArray+TLV8Additions.h
//  ap2-sender
//
//  Created by Viktoriia on 13.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "TLV8Item.h"

NS_ASSUME_NONNULL_BEGIN

@interface NSArray (TLV8Additions)

- (TLV8Item *)itemWithTag:(TLV8Tag)tag;

@end

NS_ASSUME_NONNULL_END
