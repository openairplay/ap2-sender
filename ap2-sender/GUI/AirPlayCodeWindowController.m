//
//  AirPlayCodeWindowController.m
//  ap2-sender
//
//  Created by Viktoriia on 14.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import "AirPlayCodeWindowController.h"

@interface AirPlayCodeWindowController ()

@end

@implementation AirPlayCodeWindowController

- (void)windowDidLoad {
    [super windowDidLoad];
    
    // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
}

- (IBAction)btnOKAction:(id)sender {
    [self.window close];
    [NSApp stopModalWithCode:NSModalResponseOK];
}

- (IBAction)btnCancelAction:(id)sender {
    [self.window close];
    [NSApp stopModalWithCode:NSModalResponseAbort];
}

#pragma mark - Control Editing Notifications

- (void)controlTextDidChange:(NSNotification *)obj {
    id sender = [obj object];
    if (sender == self.textFieldCode) {
        if (self.textFieldCode.stringValue.length == 0)
            [self.btnOK setEnabled:NO];
        else
            [self.btnOK setEnabled:YES];
    }
}
@end
