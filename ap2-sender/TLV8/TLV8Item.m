//
//  TLV8Item.m
//  ap2-sender
//
//  Created by Viktoriia on 13.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import "TLV8Item.h"

@implementation TLV8Item

- (instancetype)initWithTag:(TLV8Tag)aTag value:(NSData *)aValue {
    self = [super init];
    if (self) {
        self.tag = aTag;
        self.value = aValue;
    }
    return self;
}

@end
