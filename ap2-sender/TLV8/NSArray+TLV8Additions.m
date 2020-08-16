//
//  NSArray+TLV8Additions.m
//  ap2-sender
//
//  Created by Viktoriia on 13.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import "NSArray+TLV8Additions.h"

@implementation NSArray (TLV8Additions)

- (TLV8Item *)itemWithTag:(TLV8Tag)tag {
    for (TLV8Item *item in self) {
        if (item.tag == tag) {
            return item;
        }
    }
    return nil;
}

@end
