//
//  AirPlayCodeWindowController.h
//  ap2-sender
//
//  Created by Viktoriia on 14.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface AirPlayCodeWindowController : NSWindowController

@property (assign) IBOutlet NSTextField *textFieldCode;
@property (assign) IBOutlet NSButton *btnOK;
@property (assign) IBOutlet NSButton *btnCancel;

- (IBAction)btnOKAction:(id)sender;
- (IBAction)btnCancelAction:(id)sender;

@end
