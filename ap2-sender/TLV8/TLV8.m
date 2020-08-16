//
//  TLV8.m
//  ap2-sender
//
//  Created by Viktoriia on 13.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import "TLV8.h"

@implementation TLV8

+ (NSArray<TLV8Item *> *)decode:(NSData *)data {
    NSMutableArray *items = [[NSMutableArray alloc] init];
    
    NSUInteger offset = 0;
    NSUInteger dataLength = data.length;
    const uint8_t *bytes = data.bytes;
    
    uint8_t previous_type = 0xff;   // Should be an unused type code, assume 0xFF
    uint16_t previous_size = 0;
    
    while (offset < dataLength) {
        uint8_t type = bytes[offset];
        offset += 1;
        uint8_t size = bytes[offset];
        offset += 1;
        NSData *itemData = [data subdataWithRange:NSMakeRange(offset, size)];
        
        // Check whether the data should be appended
        if (type == previous_type && previous_size == 255) {
            uint8_t index = items.count - 1;
            TLV8Item *oldItem = [items objectAtIndex:index];
            NSData *oldData = oldItem.value;
            NSMutableData *newData = [[NSMutableData alloc] initWithData:oldData];
            [newData appendData:itemData];
            oldItem.value = newData;
        } else {
            TLV8Item *newItem = [[TLV8Item alloc] initWithTag:type value:itemData];
            [items addObject:newItem];
        }
        
        offset += size;
        
        // Save previous values
        previous_type = type;
        previous_size = size;
    }
    
    return items;
}

+ (int)encode:(NSArray<TLV8Item *> *)items toBytes:(uint8_t **)stream_ptr {
    uint8_t * stream = *stream_ptr;
    
    uint32_t offset = 0;
    uint32_t data_offset = 0;
    uint8_t previous_type = 0xff;   // Should be an unused type code, assume 0xFF
    uint16_t remaining_bytes = 0;
    
    NSUInteger count = items.count;
    for (int i = 0; i < count; i++) {
        TLV8Item *item = items[i];
        uint8_t type = item.tag;
        uint8_t *data = (uint8_t *)item.value.bytes;
        uint16_t size = item.value.length;
        
        // Split encoded object into two or more consecutive segments
        previous_type = type;
        remaining_bytes = size;
        data_offset = 0;
        
        while (remaining_bytes > 0) {
            // Initialize or reallocate the stream buffer as needed
            uint16_t data_size = (remaining_bytes >= 255) ? 255 : remaining_bytes;
            if (i == 0) {
                uint8_t *mem = (uint8_t *)malloc(data_size + 2);
                if (NULL == mem) {
                    return 0;
                } else {
                    stream = mem;
                }
            } else {
                uint8_t *mem = (uint8_t *)realloc(stream, offset + data_size + 2);
                if (NULL == mem) {
                    return 0;
                } else {
                    stream = mem;
                }
            }
            
            stream[offset] = type;
            stream[offset+1] = data_size;
            memcpy(stream + offset + 2, data + data_offset, data_size);

            offset += data_size + 2;
            
            remaining_bytes = remaining_bytes - data_size;
            
            data_offset += data_size;
        }
    }
    
    *stream_ptr = stream;
    
    return offset;
}

@end
