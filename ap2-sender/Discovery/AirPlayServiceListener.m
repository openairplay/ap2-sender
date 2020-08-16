//
//  AirPlayServiceListener.m
//  ap2-sender
//
//  Created by Viktoriia on 14.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import "AirPlayServiceListener.h"
#import "AirPlayService.h"

#import <sys/socket.h>
#import <sys/types.h>
#include <arpa/inet.h>

@interface AirPlayServiceListener () <NSNetServiceBrowserDelegate, NSNetServiceDelegate>

@property (strong)              NSNetServiceBrowser     *airPlayServiceBrowser;
@property (strong, readwrite)   NSMutableArray          *foundDevices;

@end

@implementation AirPlayServiceListener

#pragma mark - Init/Dealloc

- (id)init {
    self = [super init];
    if (self) {
        _airPlayServiceBrowser = [[NSNetServiceBrowser alloc] init];
        [_airPlayServiceBrowser setDelegate:self];
        _foundDevices = [[NSMutableArray alloc] init];
        _delegate = nil;
    }
    return self;
}

- (void)dealloc {
    _airPlayServiceBrowser.delegate = nil;
}

#pragma mark - Starting/Stopping AirPlay Service Discovery

- (void)startBrowsingForAirPlayServices {
    [self.airPlayServiceBrowser searchForServicesOfType:@"_airplay._tcp" inDomain:@""];
}

- (void)stopBrowsingForAirPlayServices {
    [self.airPlayServiceBrowser stop];
}

#pragma mark - Resolving AirPlay Services

- (void)resolveAirPlayServices {
    for (int i = 0; i < self.foundDevices.count; i++) {
        AirPlayService *airPlayService = [self.foundDevices objectAtIndex:i];
        NSNetService *service = airPlayService.netService;
        service.delegate = self;
        [service resolveWithTimeout:20];
        [service startMonitoring];
    }
}

#pragma mark - NSNetServiceBrowserDelegate Protocol Support

- (void)netServiceBrowser:(NSNetServiceBrowser *)aNetServiceBrowser didFindService:(NSNetService *)aNetService moreComing:(BOOL)moreComing {
    NSLog(@"%s: %@", __PRETTY_FUNCTION__, aNetService.name);
    NSString *discoveredServiceName = aNetService.name;
    AirPlayService *airPlayService = [[AirPlayService alloc] initWithNetService:aNetService];
    airPlayService.name = discoveredServiceName;
    [self.foundDevices addObject:airPlayService];
    if (!moreComing) {
        [self resolveAirPlayServices];
    }
    [self informDelegate];
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)aNetServiceBrowser didRemoveService:(NSNetService *)aNetService moreComing:(BOOL)moreComing {
    NSLog(@"%s: %@", __PRETTY_FUNCTION__, aNetService.name);
    AirPlayService *airPlayServiceToRemove = nil;
    for (AirPlayService *airPlayService in self.foundDevices) {
        if ([airPlayService.netService isEqualTo:aNetService]) {
            airPlayServiceToRemove = airPlayService;
        }
    }
    if (airPlayServiceToRemove) {
        [self.foundDevices removeObject:airPlayServiceToRemove];
    }
    [self informDelegate];
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)aNetServiceBrowser didNotSearch:(NSDictionary *)errorDict {
    NSLog(@"%s", __PRETTY_FUNCTION__);
    [self informDelegate];
}

#pragma mark - NSNetServiceDelegate Protocol Support

- (void)netServiceDidResolveAddress:(NSNetService *)sender {
    // Tells the delegate that the NSNetService object has added an address to its list
    // of addresses for the service. However, more addresses may be added.
    // For example, in systems that support both IPv4 and IPv6,
    // netServiceDidResolveAddress: may be called two or more times —
    // once for the IPv4 address and again for the IPv6 address
    NSArray *addresses = [sender addresses];
    char buffer[256];
    uint16_t port;
    
    AirPlayService *resolvedAirPlayService = nil;
    for (AirPlayService *airPlayService in self.foundDevices) {
        if ([airPlayService.netService isEqualTo:sender]) {
            resolvedAirPlayService = airPlayService;
        }
    }
    if (resolvedAirPlayService == nil) {
        return;
    }
    
    for (NSData *addressData in addresses) {
        struct sockaddr *address;
        address = (struct sockaddr *)[addressData bytes];
        switch (address->sa_family) {
                //IPv6
            case AF_INET6:
            {
                struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
                if (inet_ntop(AF_INET6, &addr6->sin6_addr, buffer, sizeof(buffer))) {
                    port = ntohs(addr6->sin6_port);
                    NSString *addr = [[NSString alloc] initWithCString:buffer encoding:NSUTF8StringEncoding];
                    [resolvedAirPlayService.ipAddresses addObject:@{@"address":addr,
                                                                    @"port":@(port),
                                                                    @"type":@"ipv6"}];
                }
                break;
            }
                
                //IPv4
            case AF_INET:
            {
                struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
                if (inet_ntop(AF_INET, &addr4->sin_addr, buffer, sizeof(buffer))) {
                    port = ntohs(addr4->sin_port);
                    NSString *ipAddr = [[NSString alloc] initWithCString:buffer encoding:NSUTF8StringEncoding];
                    [resolvedAirPlayService.ipAddresses addObject:@{@"address":ipAddr,
                                                                    @"port":@(port),
                                                                    @"type":@"ipv4"}];
                }
                break;
            }
                
            default:
                break;
        }
    }
    NSLog(@"%s:\n%@", __PRETTY_FUNCTION__, resolvedAirPlayService.description);
    [self informDelegate];
}

- (void)netService:(NSNetService *)sender didNotResolve:(NSDictionary *)errorDict {
//    int errorCode = [[errorDict objectForKey:NSNetServicesErrorCode] intValue];
//    NSLog(@"Did not resolve %@ (error code: %d).", sender.name, errorCode);
}

- (void)netService:(NSNetService *)sender didUpdateTXTRecordData:(NSData *)data {
    AirPlayService *airPlayServiceToUpdate = nil;
    for (AirPlayService *airPlayService in self.foundDevices) {
        if ([airPlayService.netService isEqualTo:sender]) {
            airPlayServiceToUpdate = airPlayService;
        }
    }
    if (airPlayServiceToUpdate == nil) {
        return;
    }
    
    NSDictionary *info = [NSNetService dictionaryFromTXTRecordData:data];
    
    NSData *deviceIDData = [info objectForKey:@"deviceid"];
    if (deviceIDData) {
        NSString *macAddress = [[NSString alloc] initWithData:deviceIDData encoding:NSUTF8StringEncoding];
        airPlayServiceToUpdate.macAddress = macAddress;
    }
    NSData *modelData = [info objectForKey:@"model"];
    if (modelData) {
        NSString *model = [[NSString alloc] initWithData:modelData encoding:NSUTF8StringEncoding];
        airPlayServiceToUpdate.model = model;
    }
    NSData *featuresData = [info objectForKey:@"features"];
    if (featuresData) {
        NSString *strFeatures = [[NSString alloc] initWithData:featuresData encoding:NSUTF8StringEncoding];
        NSArray *featuresComponents = [strFeatures componentsSeparatedByString:@","];
        if (featuresComponents.count == 2) {
            //For example, the features set 0x1111111122222222 will be declared as "0x22222222,0x11111111"
            NSString *firstValue = [featuresComponents firstObject];
            NSScanner *scanner = [[NSScanner alloc] initWithString:firstValue];
            unsigned int features1 = 0;
            [scanner scanHexInt:&features1];
            
            NSString *secondValue = [featuresComponents objectAtIndex:1];
            NSScanner *scanner2 = [[NSScanner alloc] initWithString:secondValue];
            unsigned int features2 = 0;
            [scanner2 scanHexInt:&features2];
            
            unsigned long allFeatures = ((unsigned long)features2 << 32) | features1;
            airPlayServiceToUpdate.features = allFeatures;
        } else {
            NSScanner *scanner = [[NSScanner alloc] initWithString:strFeatures];
            unsigned int features = 0;
            [scanner scanHexInt:&features];
            airPlayServiceToUpdate.features = features;
        }
    }
    NSData *srcversData = [info objectForKey:@"srcvers"];
    if (srcversData) {
        NSString *srcvers = [[NSString alloc] initWithData:srcversData encoding:NSUTF8StringEncoding];
        airPlayServiceToUpdate.serverVersion = srcvers;
    }
    NSData *pwData = [info objectForKey:@"pw"];
    if (pwData) {
        BOOL isPasswordProtected = NO;
        NSString *strPW = [[NSString alloc] initWithData:pwData encoding:NSUTF8StringEncoding];
        isPasswordProtected = [strPW boolValue];
        airPlayServiceToUpdate.passwordProtected = isPasswordProtected;
    }
    NSData *pinData = [info objectForKey:@"pin"];
    if (pinData) {
        BOOL isPasscodeProtected = NO;
        NSString *strPin = [[NSString alloc] initWithData:pinData encoding:NSUTF8StringEncoding];
        isPasscodeProtected = [strPin boolValue];
        airPlayServiceToUpdate.passcodeProtected = isPasscodeProtected;
    }
    NSData *flags = [info objectForKey:@"flags"];
    if (flags) {
        NSString *strFlags = [[NSString alloc] initWithData:flags encoding:NSUTF8StringEncoding];
        NSScanner *scanner = [[NSScanner alloc] initWithString:strFlags];
        unsigned int flags = 0;
        [scanner scanHexInt:&flags];
        BOOL isDeviceVerificationEnabled = (0 < (flags & (1 << 9)));
        airPlayServiceToUpdate.deviceVerificationEnabled = isDeviceVerificationEnabled;
    }
    NSData *protocolVersionData = [info objectForKey:@"vv"];
    if (protocolVersionData) {
        NSString *strProtocolVersion = [[NSString alloc] initWithData:protocolVersionData encoding:NSUTF8StringEncoding];
        int protocolVersion = strProtocolVersion.intValue;
        airPlayServiceToUpdate.protocolVersion = protocolVersion;
    }
    NSLog(@"%s:\n%@", __PRETTY_FUNCTION__, airPlayServiceToUpdate.description);
}

- (void)informDelegate {
    if (self.delegate && [self.delegate respondsToSelector:@selector(airPlayServiceListenerFoundDevicesDidChange:)]) {
        [self.delegate airPlayServiceListenerFoundDevicesDidChange:self];
    }
}

@end
