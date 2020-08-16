//
//  AirPlayServiceListener.m
//  ap2-sender
//
//  Created by Viktoriia on 14.08.2020.
//  Copyright © 2020 Viktoriia. All rights reserved.
//

#import "AirPlayServiceListener.h"
#import "AirPlayConstants.h"
#import "AirPlayService.h"
#import "AppDelegate.h"
#import "AppDelegate+Streaming.h"
#import "DeclarationsNMacroses.h"
#import "EPNotifications.h"
#import "EPAirPlayReceiver.h"

#import <sys/socket.h>
#import <sys/types.h>
#include <arpa/inet.h>

@interface AirPlayServiceListener () <NSNetServiceBrowserDelegate, NSNetServiceDelegate>

@property (strong) NSNetServiceBrowser *airPlayServiceBrowser;

@end

@implementation AirPlayServiceListener

- (id)init {
    self = [super init];
    if (self) {
        _airPlayServiceBrowser = [[NSNetServiceBrowser alloc] init];
        [_airPlayServiceBrowser setDelegate:self];
    }
    return self;
}

- (void)dealloc {
    _airPlayServiceBrowser.delegate = nil;
}

#pragma mark - Starting/Stopping AirPlay Service Discovery

- (void)searchForAirPlayServices {
    [self.airPlayServiceBrowser searchForServicesOfType:AIRPLAY_SERVER_TYPE inDomain:@""];
}

- (void)stopSearchingForAirPlayServices {
    [self.airPlayServiceBrowser stop];
}

#pragma mark - Resolving AirPlay Services

- (void)resolveAirPlayServices {
    for (int i = 0; i < sharedAppDelegate.discoveredAirPlayServices.count; i++) {
        EPAirPlayService *airPlayService = [sharedAppDelegate.discoveredAirPlayServices objectAtIndex:i];
        NSNetService *service = airPlayService.netService;
        service.delegate = self;
        [service resolveWithTimeout:20];
        [service startMonitoring];
    }
}

#pragma mark - NSNetServiceBrowserDelegate Protocol Support

- (void)netServiceBrowser:(NSNetServiceBrowser *)aNetServiceBrowser didFindService:(NSNetService *)aNetService moreComing:(BOOL)moreComing {
    EPAirPlaySenderLog(@"[AirPlay] Device found: %@", aNetService.name);
    NSString *discoveredServiceName = aNetService.name;
    EPAirPlayServer *airPlayReceiver = EPAirPlayReceiver.sharedReceiver.airPlayServer;
    BOOL ownService = (airPlayReceiver != nil) && (airPlayReceiver.isRunning) && [airPlayReceiver.publishedName isEqualToString:discoveredServiceName];
    if (!ownService) { //skip own service
        AirPlayService *airPlayService = [[AirPlayService alloc] initWithNetService:aNetService];
        airPlayService.name = discoveredServiceName;
        [sharedAppDelegate.discoveredAirPlayServices addObject:airPlayService];
    }
    if (!moreComing) {
        [self resolveAirPlayServices];
    }
    [[NSNotificationCenter defaultCenter] postNotificationName:EPNotificationAirPlayServiceDidChange object:nil];
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)aNetServiceBrowser didRemoveService:(NSNetService *)aNetService moreComing:(BOOL)moreComing {
    EPAirPlaySenderLog(@"[AirPlay] Device disappeared: %@", aNetService.name);
    AirPlayService *airPlayServiceToRemove = nil;
    for (EPAirPlayService *airPlayService in sharedAppDelegate.discoveredAirPlayServices) {
        if ([airPlayService.netService isEqualTo:aNetService]) {
            airPlayServiceToRemove = airPlayService;
        }
    }
    if (airPlayServiceToRemove) {
        [sharedAppDelegate fallbackToComputerIfNeededWhenServiceDidDisappear:airPlayServiceToRemove];
        [sharedAppDelegate.discoveredAirPlayServices removeObject:airPlayServiceToRemove];
    }
    [[NSNotificationCenter defaultCenter] postNotificationName:EPNotificationAirPlayServiceDidChange object:nil];
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)aNetServiceBrowser didNotSearch:(NSDictionary *)errorDict {
    EPAirPlaySenderLog(@"[AirPlay] Search failed");
    [[NSNotificationCenter defaultCenter] postNotificationName:EPNotificationAirPlayServiceDidChange object:nil];
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
    for (EPAirPlayService *airPlayService in sharedAppDelegate.discoveredAirPlayServices) {
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
    [[NSNotificationCenter defaultCenter] postNotificationName:EPNotificationAirPlayServiceDidChange object:nil];
    EPAirPlaySenderLog(@"[AirPlay] Resolved: %@", resolvedAirPlayService.description);
}

- (void)netService:(NSNetService *)sender didNotResolve:(NSDictionary *)errorDict {
    int errorCode = [[errorDict objectForKey:NSNetServicesErrorCode] intValue];
    EPAirPlaySenderLog(@"[AirPlay] Did not resolve %@ (error code: %d).", sender.name, errorCode);
    
//    EPAirPlayService *airPlayServiceToRemove = nil;
//    for (EPAirPlayService *airPlayService in sharedAppDelegate.discoveredAirPlayServices) {
//        if ([airPlayService.netService isEqualTo:sender]) {
//            airPlayServiceToRemove = airPlayService;
//        }
//    }
//    if (airPlayServiceToRemove) {
//        [sharedAppDelegate.discoveredAirPlayServices removeObject:airPlayServiceToRemove];
//    }
//    
//    [[NSNotificationCenter defaultCenter] postNotificationName:EPNotificationAirPlayServiceDidChange object:nil];
}

- (void)netService:(NSNetService *)sender didUpdateTXTRecordData:(NSData *)data {
    AirPlayService *airPlayServiceToUpdate = nil;
    for (EPAirPlayService *airPlayService in sharedAppDelegate.discoveredAirPlayServices) {
        if ([airPlayService.netService isEqualTo:sender]) {
            airPlayServiceToUpdate = airPlayService;
        }
    }
    if (airPlayServiceToUpdate == nil) {
        return;
    }
    
    NSDictionary *info = [NSNetService dictionaryFromTXTRecordData:data];
    //    deviceid = <43383a36 393a4344 3a33383a 36413a30 43>;
    //    features = <30783541 37464646 46372c30 784445>;
    //    flags = <30786334>;
    //    model = <4170706c 65545635 2c33>;
    //    pi = <66306131 39346133 2d386530 332d3437 36342d62 3463332d 35313139 36376133 32623762>;
    //    pk = <65373837 65366631 32326165 63643562 36373563 30383261 64316135 34643635 65613432 62346336 63623236 61633930 30393966 30623866 32653532 31613963>;
    //    pw = <31>;
    //    srcvers = <3236382e 31>;
    //    vv = <32>;
    
    //    AirServer
    //    TXTRecordData: {
    //        deviceid = <34303a36 433a3846 3a30443a 31313a36 31>;
    //        features = <30783541 37464646 46372c30 783145>;
    //        flags = <307834>;
    //        model = <4170706c 65545633 2c32>;
    //        pi = <30346435 64643165 2d303036 352d3439 37372d39 3466622d 63353332 36323562 35653763>;
    //        pk = <34306633 33333964 30356162 34656535 36376539 31613166 62663262 32646433 39313034 33386231 63323633 66313663 37356531 33356239 64643433 37663962>;
    //        srcvers = <3232302e 3638>;
    //        vv = <32>;
    //    }
    
    //    C869CD386A0C@Apple TV
    //    2015-12-25 09:50:50.450 Elmedia Player[957:15462] TXTRecordData: {
    //        am = <4170706c 65545635 2c33>;
    //        cn = <302c312c 322c33>;
    //        da = <74727565>;
    //        et = <302c332c 35>;
    //        ft = <30783541 37464646 46372c30 784445>;
    //        md = <302c312c 32>;
    //        pk = <65373837 65366631 32326165 63643562 36373563 30383261 64316135 34643635 65613432 62346336 63623236 61633930 30393966 30623866 32653532 31613963>;
    //        pw = <74727565>;
    //        sf = <30786334>;
    //        tp = <554450>;
    //        vn = <36353533 37>;
    //        vs = <3236382e 31>;
    //        vv = <32>;
    //    }
    
//#ifdef AIRPLAY_LOG
//    DebugLog(@"TXTRecordData: %@", info.description);
//    for (NSString *key in info) {
//        NSData *data = [info objectForKey:key];
//        NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
//        DebugLog(@"%@=%@", key, str);
//    }
//#endif
    
    //    NSData *flagsData = [info objectForKey:@"flags"];
    //    unsigned int flags = 0;
    //    if (flagsData) {
    //        NSString *strFlags = [[NSString alloc] initWithData:flagsData encoding:NSUTF8StringEncoding];
    //        NSScanner *scanner = [[NSScanner alloc] initWithString:strFlags];
    //        [scanner scanHexInt:&flags];
    //    }
    //
    //    NSData *vvData = [info objectForKey:@"vv"];
    //    NSString *vv = nil;
    //    if (vvData) {
    //        vv = [[NSString alloc] initWithData:vvData encoding:NSUTF8StringEncoding];
    //    }
    //    NSData *piData = [info objectForKey:@"pi"];
    //    NSString *pi = nil;
    //    if (piData) {
    //        pi = [[NSString alloc] initWithData:piData encoding:NSUTF8StringEncoding];
    //    }
    //    NSData *pkData = [info objectForKey:@"pk"];
    //    NSString *pk = nil;
    //    if (pkData) {
    //        pk = [[NSString alloc] initWithData:pkData encoding:NSUTF8StringEncoding];
    //    }
    
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
    if ([info objectForKey:@"gid"] || [info objectForKey:@"igl"] || [info objectForKey:@"gcgl"]) {
        airPlayServiceToUpdate.airPlay2Supported = YES;
    }
    
//    NSData *pkData = [info objectForKey:@"pk"];
//    if (pkData) {
//        NSString *pk = [[[NSString alloc] initWithData:pkData encoding:NSUTF8StringEncoding] autorelease];
//        NSLog(@"pk = %@", pk);
//    }
    EPAirPlaySenderLog(@"[AirPlay] TXT record updated: %@", airPlayServiceToUpdate.description);
}

@end
