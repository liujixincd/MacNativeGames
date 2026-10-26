/* Called only after runtime_game_slot_acquire, before guest code or save writes.
   The runtime owns the lock throughout the copy and the subsequent game. */
#include "runtime.h"
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
void runtime_cheats_backup(void) {}
#else
#import <Foundation/Foundation.h>
#include "game_data.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static void backup_failed(NSString *problem) {
    fprintf(stderr, "[totk] cheat profile backup: %s\n", problem.UTF8String);
    runtime_fail("Cannot protect the profile before enabling cheats; see the backup error");
}

void runtime_cheats_backup(void) {
    @autoreleasepool {
        char path[4096];
        runtime_game_data_path("cheats-selection.json", path, sizeof path);
        NSFileManager *fm = NSFileManager.defaultManager;
        NSError *error = nil;
        NSData *data = [NSData dataWithContentsOfFile:@(path) options:0 error:&error];
        if (!data) {
            if ([error.domain isEqualToString:NSCocoaErrorDomain] && error.code == NSFileReadNoSuchFileError) return;
            backup_failed(error.localizedDescription ?: @"Cannot read the cheat selection");
        }
        id selection = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
        NSString *fingerprint = [selection isKindOfClass:NSDictionary.class] ? selection[@"patch_sha256"] : nil;
        NSCharacterSet *hex = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
        if (![fingerprint isKindOfClass:NSString.class] || fingerprint.length != 64 ||
            [fingerprint rangeOfCharacterFromSet:hex.invertedSet].location != NSNotFound)
            backup_failed(@"The cheat selection record is invalid; rebuild the app");
        const char *env = getenv("TOTK_PROFILE_DIR");
        NSString *profile = env && *env ? @(env) : @"user-data";
        NSDictionary *attributes = [fm attributesOfItemAtPath:profile error:&error];
        if (!attributes) {
            if ([error.domain isEqualToString:NSCocoaErrorDomain] && error.code == NSFileReadNoSuchFileError) return; // no profile yet
            backup_failed(error.localizedDescription ?: @"Cannot inspect the profile");
        }
        if (![attributes[NSFileType] isEqualToString:NSFileTypeDirectory]) backup_failed(@"The profile is not a directory");
        NSString *backup = [profile stringByAppendingFormat:@"-before-cheats-%@", [fingerprint substringToIndex:16]];
        error = nil;
        attributes = [fm attributesOfItemAtPath:backup error:&error];
        if (attributes) {
            if (![attributes[NSFileType] isEqualToString:NSFileTypeDirectory]) backup_failed(@"The backup path is not a directory");
            return;
        }
        if (!([error.domain isEqualToString:NSCocoaErrorDomain] && error.code == NSFileReadNoSuchFileError))
            backup_failed(error.localizedDescription ?: @"Cannot inspect the backup path");
        NSString *temporary = [backup stringByAppendingFormat:@".copy-%@", NSUUID.UUID.UUIDString];
        if (![fm copyItemAtPath:profile toPath:temporary error:&error] ||
            ![fm moveItemAtPath:temporary toPath:backup error:&error]) {
            [fm removeItemAtPath:temporary error:nil];
            backup_failed(error.localizedDescription ?: @"Cannot copy the profile");
        }
        fprintf(stderr, "[totk] cheats: profile backed up to %s\n", backup.fileSystemRepresentation);
    }
}
#endif
