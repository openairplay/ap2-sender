//
//  AppDelegate.m
//  ap2-sender
//
//  Created by Viktoriia on 14.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import "AppDelegate.h"
#import "AirPlayServiceListener.h"
#import "AirPlayService.h"
#import "AirPlaySenderConnection.h"
#import "AirPlayCodeWindowController.h"

@interface AppDelegate () <AirPlayServiceListenerDelegate, AirPlaySenderConnectionDelegate>

@property (weak) IBOutlet NSWindow      *window;
@property (weak) IBOutlet NSPopUpButton *popUpBtnDevices;

@property (strong) AirPlayServiceListener   *airPlayServiceListener;
@property (strong) AirPlaySenderConnection  *airPlaySenderConnection;

@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    // Insert code here to initialize your application
    [self.popUpBtnDevices removeAllItems];
    
    self.airPlayServiceListener = [[AirPlayServiceListener alloc] init];
    [self.airPlayServiceListener startBrowsingForAirPlayServices];
    self.airPlayServiceListener.delegate = self;
}


- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
    
    [self.airPlaySenderConnection close];
    [self.airPlayServiceListener stopBrowsingForAirPlayServices];
}

#pragma mark - AirPlayServiceListenerDelegate Protocol Support

- (void)airPlayServiceListenerFoundDevicesDidChange:(AirPlayServiceListener *)listener {
    [self.popUpBtnDevices removeAllItems];
    NSMenu *menuDevices = [NSMenu new];
    for (int i = 0; i < listener.foundDevices.count; i++) {
        AirPlayService *airPlayService = [listener.foundDevices objectAtIndex:i];
        [menuDevices addItemWithTitle:airPlayService.name action:NULL keyEquivalent:@""];
    }
    [self.popUpBtnDevices setMenu:menuDevices];
}

#pragma mark - AirPlaySenderConnectionDelegate Protocol Support

- (NSString *)promptUserForPin {
    [NSApp activateIgnoringOtherApps:YES];
    NSString *code = nil;
    AirPlayCodeWindowController *airPlayCodeController = [[AirPlayCodeWindowController alloc] initWithWindowNibName:@"AirPlayCodeWindowController"];
    NSInteger result = [NSApp runModalForWindow:airPlayCodeController.window];
    if (result == NSModalResponseOK) {
        code = airPlayCodeController.textFieldCode.stringValue;
    }
    return code;
}

#pragma mark - Sent Actions

- (IBAction)pairDevice:(id)sender {
    NSInteger selectedDeviceIndex = [self.popUpBtnDevices indexOfSelectedItem];
    if (selectedDeviceIndex == -1 || selectedDeviceIndex >= self.airPlayServiceListener.foundDevices.count) {
        return;
    }
    AirPlayService *device = [self.airPlayServiceListener.foundDevices objectAtIndex:selectedDeviceIndex];
    self.airPlaySenderConnection = [[AirPlaySenderConnection alloc] initWithHostAddress:device.primaryIPv4Address name:nil port:(int)device.netService.port];
    self.airPlaySenderConnection.delegate = self;
    [self.airPlaySenderConnection setup];
    [self.airPlaySenderConnection startPairing];
}

@end
