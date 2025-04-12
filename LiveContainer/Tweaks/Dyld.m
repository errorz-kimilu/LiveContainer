//
//  Dyld.m
//  LiveContainer
//
//  Created by s s on 2025/2/7.
//
#include <dlfcn.h>
#include <stdlib.h>
#import "../../fishhook/fishhook.h"
#import "../utils.h"
#include <sys/mman.h>
@import Darwin;
@import Foundation;
@import MachO;

typedef uint32_t dyld_platform_t;

typedef struct {
    dyld_platform_t platform;
    uint32_t        version;
} dyld_build_version_t;

uint32_t lcImageIndex = 0;
uint32_t tweakLoaderIndex = 0;
uint32_t appMainImageIndex = 0;
void* appExecutableHandle = 0;
bool tweakLoaderLoaded = false;
bool appExecutableFileTypeOverwritten = false;

void* (*orig_dlsym)(void * __handle, const char * __symbol);
uint32_t (*orig_dyld_image_count)(void);
const struct mach_header* (*orig_dyld_get_image_header)(uint32_t image_index);
intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t image_index);
const char* (*orig_dyld_get_image_name)(uint32_t image_index);

uint32_t guestAppSdkVersion = 0;
uint32_t guestAppSdkVersionSet = 0;
bool (*orig_dyld_program_sdk_at_least)(void* dyldPtr, dyld_build_version_t version);
uint32_t (*orig_dyld_get_program_sdk_version)(void* dyldPtr);

bool _dyld_get_image_uuid(const struct mach_header* mh, uuid_t uuid);

static void overwriteAppExecutableFileType(void) {
    struct mach_header_64* appImageMachOHeader = (struct mach_header_64*) orig_dyld_get_image_header(appMainImageIndex);
    kern_return_t kret = builtin_vm_protect(mach_task_self(), (vm_address_t)appImageMachOHeader, sizeof(appImageMachOHeader), false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
    if(kret != KERN_SUCCESS) {
        NSLog(@"[LC] failed to change appImageMachOHeader to rw");
    } else {
        NSLog(@"[LC] changed appImageMachOHeader to rw");
        appImageMachOHeader->filetype = MH_EXECUTE;
        builtin_vm_protect(mach_task_self(), (vm_address_t)appImageMachOHeader, sizeof(appImageMachOHeader), false,  PROT_READ);
    }
}

static inline int translateImageIndex(int origin) {
    if(origin == lcImageIndex) {
        if(!appExecutableFileTypeOverwritten) {
            overwriteAppExecutableFileType();
            appExecutableFileTypeOverwritten = true;
        }
        
        return appMainImageIndex;
    }
    
    // find tweakloader index
    if(tweakLoaderLoaded && tweakLoaderIndex == 0) {
        const char* tweakloaderPath = [[[[NSUserDefaults lcMainBundle] bundlePath] stringByAppendingPathComponent:@"Frameworks/TweakLoader.dylib"] UTF8String];
        uint32_t imageCount = orig_dyld_image_count();
        for(uint32_t i = imageCount - 1; i >= 0; --i) {
            const char* imgName = orig_dyld_get_image_name(i);
            if(strcmp(imgName, tweakloaderPath) == 0) {
                tweakLoaderIndex = i;
                break;
            }
        }
        if(tweakLoaderIndex == 0) {
            tweakLoaderIndex = -1; // can't find, don't search again in the future
        }
    }
    
    if(tweakLoaderLoaded && tweakLoaderIndex > 0 && origin >= tweakLoaderIndex) {
        return origin + 2;
    } else if(origin >= appMainImageIndex) {
        return origin + 1;
    }
    return origin;
}


void* hook_dlsym(void * __handle, const char * __symbol) {
    if(__handle == (void*)RTLD_MAIN_ONLY) {
        if(strcmp(__symbol, MH_EXECUTE_SYM) == 0) {
            if(!appExecutableFileTypeOverwritten) {
                overwriteAppExecutableFileType();
                appExecutableFileTypeOverwritten = true;
            }
            return (void*)orig_dyld_get_image_header(appMainImageIndex);
        }
        __handle = appExecutableHandle;
    }
    
    __attribute__((musttail)) return orig_dlsym(__handle, __symbol);
}

uint32_t hook_dyld_image_count(void) {
    return orig_dyld_image_count() - 1 - (uint32_t)tweakLoaderLoaded;
}

const struct mach_header* hook_dyld_get_image_header(uint32_t image_index) {
    __attribute__((musttail)) return orig_dyld_get_image_header(translateImageIndex(image_index));
}

intptr_t hook_dyld_get_image_vmaddr_slide(uint32_t image_index) {
    __attribute__((musttail)) return orig_dyld_get_image_vmaddr_slide(translateImageIndex(image_index));
}

const char* hook_dyld_get_image_name(uint32_t image_index) {
    __attribute__((musttail)) return orig_dyld_get_image_name(translateImageIndex(image_index));
}

void *findPrivateSymbol(struct mach_header_64 *header, const char *name) {
    uintptr_t slide = 0;
    uint8_t *linkedit_base = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;
    struct symtab_command* symtab_cmd = NULL;
    uintptr_t cur = (uintptr_t)header + sizeof(struct mach_header_64);
    struct load_command *cmd;
    for(uint i = 0; i < header->ncmds; i++, cur += cmd->cmdsize) {
        cmd = (struct load_command *)cur;
        switch(cmd->cmd) {
            case LC_SEGMENT_64: {
                const struct segment_command_64* seg = (struct segment_command_64 *)cmd;
                if(!strcmp(seg->segname, "__TEXT"))
                    slide = (uintptr_t)header - seg->vmaddr;
                if(!strcmp(seg->segname, "__LINKEDIT"))
                    linkedit_base = (uint8_t *)(seg->vmaddr - seg->fileoff + slide);
            } break;
            case LC_DYSYMTAB:
                dysymtab_cmd = (struct dysymtab_command*)cmd;
                break;
            case LC_SYMTAB:
                symtab_cmd = (struct symtab_command *)cmd;
                break;
        }
    }
    assert(linkedit_base && dysymtab_cmd && symtab_cmd);
    const struct nlist_64 *symtab = (const struct nlist_64 *)(linkedit_base + symtab_cmd->symoff);
    const char *strtab = (const char *)(linkedit_base + symtab_cmd->stroff);
    const struct nlist_64* local_start = &symtab[dysymtab_cmd->ilocalsym];
    const struct nlist_64* local_end = &local_start[dysymtab_cmd->nlocalsym];
    for (const struct nlist_64* s = local_start; s < local_end; s++) {
         if ((s->n_type & N_TYPE) == N_SECT && (s->n_type & N_STAB) == 0) {
            const char* curr_name = &strtab[s->n_un.n_strx];
            if (!strcmp(curr_name, name))
                return (void *)(s->n_value + slide);
        }
    }
    return NULL;
}

bool hook_dyld_program_sdk_at_least(void* dyldApiInstancePtr, dyld_build_version_t version) {
    if(version.platform == 0xffffffff){
        return version.version <= guestAppSdkVersionSet;
    } else {
        return version.version <= guestAppSdkVersion;
    }
}

uint32_t hook_dyld_get_program_sdk_version(void* dyldApiInstancePtr) {
    return guestAppSdkVersion;
}


bool performHookDyldApi(const char* functionName, uint32_t adrpOffset, void** origFunction, void* hookFunction) {
    
    uint32_t* baseAddr = dlsym(RTLD_DEFAULT, functionName);
    /*
    1ad450b90  e10300aa   mov     x1, x0
    1ad450b94  487b2090   adrp    x8, dyld4::gAPIs
    1ad450b98  000140f9   ldr     x0, [x8]  {dyld4::gAPIs}
    1ad450b9c  100040f9   ldr     x16, [x0]
    1ad450ba0  f10300aa   mov     x17, x0
    1ad450ba4  517fecf2   movk    x17, #0x63fa, lsl #0x30
    1ad450ba8  301ac1da   autda   x16, x17
    1ad450bac  114780d2   mov     x17, #0x238
    1ad450bb0  1002118b   add     x16, x16, x17
     */
    uint32_t* adrpInstPtr = baseAddr + adrpOffset;
    if ((*adrpInstPtr & 0x9f000000) != 0x90000000) {
        NSLog(@"[LC] not an adrp instruction");
        return false;
    }
    uint32_t immlo = (*adrpInstPtr & 0x60000000) >> 29;
    uint32_t immhi = (*adrpInstPtr & 0xFFFFE0) >> 5;
    int64_t imm = (((int64_t)((immhi << 2) | immlo)) << 43) >> 31;
    
    void* gdyldPtr = (void*)(((uint64_t)baseAddr & 0xfffffffffffff000) + imm);
    void* vtablePtr = **(void***)gdyldPtr;
    
    uint32_t* movInstPtr = baseAddr + adrpOffset + 6;
    if ((*movInstPtr & 0x7F800000) != 0x52800000) {
        NSLog(@"[LC] not an mov instruction");
        return false;
    }
    uint32_t imm16 = (*movInstPtr & 0x1FFFE0) >> 5;
    
    void* vtableFunctionPtr = vtablePtr + imm16;
    
    kern_return_t ret = builtin_vm_protect(mach_task_self(), (mach_vm_address_t)vtableFunctionPtr, sizeof(uintptr_t), false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
    if(ret != KERN_SUCCESS) {
        NSLog(@"[LC] builtin_vm_protect failed");
        return false;
    }
    *origFunction = (void*)*(void**)vtableFunctionPtr;
    *(uint64_t*)vtableFunctionPtr = (uint64_t)hookFunction;
    builtin_vm_protect(mach_task_self(), (mach_vm_address_t)vtableFunctionPtr, sizeof(uintptr_t), false, PROT_READ);
    return true;
}

bool initGuestSDKVersionInfo(void) {
    
    int fd = open("/usr/lib/dyld", O_RDONLY, 0400);
    struct stat s;
    fstat(fd, &s);
    void *map = mmap(NULL, s.st_size, PROT_READ , MAP_PRIVATE, fd, 0);
    void* findVersionSetPtr = findPrivateSymbol(map, "__ZNK5dyld413ProcessConfig7Process24findVersionSetEquivalentEN5dyld38PlatformEj");
    munmap(map, s.st_size);
    close(fd);
    if(!findVersionSetPtr) {
        NSLog(@"[LC] failed to find findVersionSetEquivalent");
        return false;
    }
    
    
    uint32_t (*realFindVersionSetPtr)(void* dyldApiInstance, uint32_t versionPlatform, uint32_t version) = getDyldBase() + (findVersionSetPtr - map);

    guestAppSdkVersionSet = realFindVersionSetPtr(0, 2, guestAppSdkVersion);
    
    return true;
}

void do_hook_loadableIntoProcess() {

    uint32_t *patchAddr = (uint32_t *)findPrivateSymbol(getDyldBase(), "__ZNK6mach_o6Header19loadableIntoProcessENS_8PlatformE7CStringb");
    size_t patchSize = sizeof(uint32_t[2]);

    kern_return_t kret;
    kret = builtin_vm_protect(mach_task_self(), (vm_address_t)patchAddr, patchSize, false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
    assert(kret == KERN_SUCCESS);

    patchAddr[0] = 0xD2800020; // mov x0, #1
    patchAddr[1] = 0xD65F03C0; // ret

    kret = builtin_vm_protect(mach_task_self(), (vm_address_t)patchAddr, patchSize, false, PROT_READ | PROT_EXEC);
    assert(kret == KERN_SUCCESS);
}


void DyldHooksInit(bool hideLiveContainer, uint32_t spoofSDKVersion) {
    // iterate through loaded images and find LiveContainer it self
    int imageCount = _dyld_image_count();
    for(int i = 0; i < imageCount; ++i) {
        const struct mach_header* currentImageHeader = _dyld_get_image_header(i);
        if(currentImageHeader->filetype == MH_EXECUTE) {
            lcImageIndex = i;
            break;
        }
    }
    
    orig_dyld_get_image_header = _dyld_get_image_header;
    
    // hook dlsym to solve RTLD_MAIN_ONLY, hook other functions to hide LiveContainer itself
    rebind_symbols((struct rebinding[5]){
        {"dlsym", (void *)hook_dlsym, (void **)&orig_dlsym},
        {"_dyld_image_count", (void *)hook_dyld_image_count, (void **)&orig_dyld_image_count},
        {"_dyld_get_image_header", (void *)hook_dyld_get_image_header, (void **)&orig_dyld_get_image_header},
        {"_dyld_get_image_vmaddr_slide", (void *)hook_dyld_get_image_vmaddr_slide, (void **)&orig_dyld_get_image_vmaddr_slide},
        {"_dyld_get_image_name", (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
    }, hideLiveContainer ? 5: 1);
    
    appExecutableFileTypeOverwritten = !hideLiveContainer;
    
    if(spoofSDKVersion) {
        guestAppSdkVersion = spoofSDKVersion;
        if(!performHookDyldApi("dyld_program_sdk_at_least", 1, (void**)&orig_dyld_program_sdk_at_least, hook_dyld_program_sdk_at_least) ||
           !performHookDyldApi("dyld_get_program_sdk_version", 0, (void**)&orig_dyld_get_program_sdk_version, hook_dyld_get_program_sdk_version) ||
           !initGuestSDKVersionInfo()) {
            return;
        }
    }
    
    if(access("/Users", F_OK) != -1) {
        // not running on macOS, skip this
        do_hook_loadableIntoProcess();
    }
}

void* getGuestAppHeader(void) {
    return (void*)orig_dyld_get_image_header(appMainImageIndex);
}
