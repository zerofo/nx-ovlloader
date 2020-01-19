#include <switch.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define DEFAULT_NRO "sdmc:/switch/.overlays/ovlmenu.ovl"

const char g_noticeText[] =
    "nx-ovlloader " VERSION "\0"
    "What's the most resilient parasite? A bacteria? A virus? An intestinal worm? An idea. Resilient, highly contagious.";

static char g_argv[2048];
static char g_nextArgv[2048];
static char g_nextNroPath[512];
u64  g_nroAddr = 0;
static u64  g_nroSize = 0;
static NroHeader g_nroHeader;
static bool g_isApplication = 0;

static u64 g_appletHeapSize = 0;
static u64 g_appletHeapReservationSize = 0;

static u128 g_userIdStorage;

static u8 g_savedTls[0x100];

// Minimize fs resource usage
u32 __nx_fs_num_sessions = 1;
u32 __nx_fsdev_direntry_cache_size = 1;
bool __nx_fsdev_support_cwd = false;

// Used by trampoline.s
Result g_lastRet = 0;

extern void* __stack_top; // Defined in libnx.
#define STACK_SIZE 0x100000 // Change this if main-thread stack size ever changes.

void __libnx_initheap(void)
{
    static char g_innerheap[0x4000];

    extern char* fake_heap_start;
    extern char* fake_heap_end;

    fake_heap_start = &g_innerheap[0];
    fake_heap_end   = &g_innerheap[sizeof g_innerheap];
}

void __appInit(void)
{
    Result rc;

    rc = smInitialize();
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 1));

    rc = setsysInitialize();
    if (R_SUCCEEDED(rc)) {
        SetSysFirmwareVersion fw;
        rc = setsysGetFirmwareVersion(&fw);
        if (R_SUCCEEDED(rc))
            hosversionSet(MAKEHOSVERSION(fw.major, fw.minor, fw.micro));
        g_appletHeapSize = (0x600000 + 0x1FFFFF) & ~0x1FFFFF;
        g_appletHeapReservationSize = 0x00;
        setsysExit();
    }

    rc = fsInitialize();
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 2));
}

void __wrap_exit(void)
{
    // exit() effectively never gets called, so let's stub it out.
    fatalThrow(MAKERESULT(Module_HomebrewLoader, 39));
}

static void*  g_heapAddr;
static size_t g_heapSize;

static void setupHbHeap(void)
{
    void* addr = NULL;
    u64 size = g_appletHeapSize;

    Result rc = svcSetHeapSize(&addr, size);

    if (R_FAILED(rc) || addr==NULL)
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 9));

    g_heapAddr = addr;
    g_heapSize = size;
}

static Handle g_procHandle;

static void procHandleReceiveThread(void* arg)
{
    Handle session = (Handle)(uintptr_t)arg;
    Result rc;

    void* base = armGetTls();
    hipcMakeRequestInline(base);

    s32 idx = 0;
    rc = svcReplyAndReceive(&idx, &session, 1, INVALID_HANDLE, UINT64_MAX);
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 15));

    HipcParsedRequest r = hipcParseRequest(base);
    if (r.meta.num_copy_handles != 1)
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 17));

    g_procHandle = r.data.copy_handles[0];
    svcCloseHandle(session);
}

static void getOwnProcessHandle(void)
{
    Result rc;

    Handle server_handle, client_handle;
    rc = svcCreateSession(&server_handle, &client_handle, 0, 0);
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 12));

    Thread t;
    rc = threadCreate(&t, &procHandleReceiveThread, (void*)(uintptr_t)server_handle, NULL, 0x1000, 0x20, 0);
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 10));

    rc = threadStart(&t);
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 13));

    hipcMakeRequestInline(armGetTls(),
        .num_copy_handles = 1,
    ).copy_handles[0] = CUR_PROCESS_HANDLE;

    svcSendSyncRequest(client_handle);
    svcCloseHandle(client_handle);

    threadWaitForExit(&t);
    threadClose(&t);
}

void loadNro(void)
{
    NroHeader* header = NULL;
    size_t rw_size=0;
    Result rc=0;

    memcpy((u8*)armGetTls() + 0x100, g_savedTls, 0x100);

    if (g_nroSize > 0)
    {
        // Unmap previous NRO.
        header = &g_nroHeader;
        rw_size = header->segments[2].size + header->bss_size;
        rw_size = (rw_size+0xFFF) & ~0xFFF;

        // .text
        rc = svcUnmapProcessCodeMemory(
            g_procHandle, g_nroAddr + header->segments[0].file_off, ((u64) g_heapAddr) + header->segments[0].file_off, header->segments[0].size);

        if (R_FAILED(rc))
            fatalThrow(MAKERESULT(Module_HomebrewLoader, 24));

        // .rodata
        rc = svcUnmapProcessCodeMemory(
            g_procHandle, g_nroAddr + header->segments[1].file_off, ((u64) g_heapAddr) + header->segments[1].file_off, header->segments[1].size);

        if (R_FAILED(rc))
            fatalThrow(MAKERESULT(Module_HomebrewLoader, 25));

       // .data + .bss
        rc = svcUnmapProcessCodeMemory(
            g_procHandle, g_nroAddr + header->segments[2].file_off, ((u64) g_heapAddr) + header->segments[2].file_off, rw_size);

        if (R_FAILED(rc))
            fatalThrow(MAKERESULT(Module_HomebrewLoader, 26));

        g_nroAddr = g_nroSize = 0;
    }

    if (g_nextNroPath[0] == '\0')
    {
        memcpy(g_nextNroPath, DEFAULT_NRO, sizeof(DEFAULT_NRO));
        memcpy(g_nextArgv,    DEFAULT_NRO, sizeof(DEFAULT_NRO));
    }

    memcpy(g_argv, g_nextArgv, sizeof g_argv);

    uint8_t *nrobuf = (uint8_t*) g_heapAddr;

    NroStart*  start  = (NroStart*)  (nrobuf + 0);
    header = (NroHeader*) (nrobuf + sizeof(NroStart));
    uint8_t*   rest   = (uint8_t*)   (nrobuf + sizeof(NroStart) + sizeof(NroHeader));
    
    rc = fsdevMountSdmc();
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 404));

    int fd = open(g_nextNroPath, O_RDONLY);
    if (fd < 0)
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 3));

    // Reset NRO path to load hbmenu by default next time.
    g_nextNroPath[0] = '\0';

    if (read(fd, start, sizeof(*start)) != sizeof(*start))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 4));

    if (read(fd, header, sizeof(*header)) != sizeof(*header))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 4));

    if (header->magic != NROHEADER_MAGIC)
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 5));

    size_t rest_size = header->size - (sizeof(NroStart) + sizeof(NroHeader));
    if (read(fd, rest, rest_size) != rest_size)
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 7));

    close(fd);
    fsdevUnmountAll();

    size_t total_size = header->size + header->bss_size;
    total_size = (total_size+0xFFF) & ~0xFFF;

    rw_size = header->segments[2].size + header->bss_size;
    rw_size = (rw_size+0xFFF) & ~0xFFF;

    int i;
    for (i=0; i<3; i++)
    {
        if (header->segments[i].file_off >= header->size || header->segments[i].size > header->size ||
            (header->segments[i].file_off + header->segments[i].size) > header->size)
        {
            fatalThrow(MAKERESULT(Module_HomebrewLoader, 6));
        }
    }

    // todo: Detect whether NRO fits into heap or not.

    // Copy header to elsewhere because we're going to unmap it next.
    memcpy(&g_nroHeader, header, sizeof(g_nroHeader));
    header = &g_nroHeader;

    u64 map_addr;

    do {
        map_addr = randomGet64() & 0xFFFFFF000ull;
        rc = svcMapProcessCodeMemory(g_procHandle, map_addr, (u64)nrobuf, total_size);

    } while (rc == 0xDC01 || rc == 0xD401);

    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 18));

    // .text
    rc = svcSetProcessMemoryPermission(
        g_procHandle, map_addr + header->segments[0].file_off, header->segments[0].size, Perm_R | Perm_X);

    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 19));

    // .rodata
    rc = svcSetProcessMemoryPermission(
        g_procHandle, map_addr + header->segments[1].file_off, header->segments[1].size, Perm_R);

    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 20));

    // .data + .bss
    rc = svcSetProcessMemoryPermission(
        g_procHandle, map_addr + header->segments[2].file_off, rw_size, Perm_Rw);

    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 21));

    u64 nro_size = header->segments[2].file_off + rw_size;
    u64 nro_heap_start = ((u64) g_heapAddr) + nro_size;
    u64 nro_heap_size  = g_heapSize + (u64) g_heapAddr - (u64) nro_heap_start;

    #define M EntryFlag_IsMandatory

    static ConfigEntry entries[] = {
        { EntryType_MainThreadHandle,     0, {0, 0} },
        { EntryType_ProcessHandle,        0, {0, 0} },
        { EntryType_AppletType,           0, {AppletType_LibraryApplet, 0} },
        { EntryType_OverrideHeap,         M, {0, 0} },
        { EntryType_Argv,                 0, {0, 0} },
        { EntryType_NextLoadPath,         0, {0, 0} },
        { EntryType_LastLoadResult,       0, {0, 0} },
        { EntryType_SyscallAvailableHint, 0, {0xffffffffffffffff, 0x9fc1fff0007ffff} },
        { EntryType_RandomSeed,           0, {0, 0} },
        { EntryType_UserIdStorage,        0, {(u64)(uintptr_t)&g_userIdStorage, 0} },
        { EntryType_HosVersion,           0, {0, 0} },
        { EntryType_EndOfList,            0, {(u64)(uintptr_t)g_noticeText, sizeof(g_noticeText)} }
    };

    ConfigEntry *entry_AppletType = &entries[2];

    if (g_isApplication) {
        entry_AppletType->Value[0] = AppletType_SystemApplication;
        entry_AppletType->Value[1] = EnvAppletFlags_ApplicationOverride;
    }

    // MainThreadHandle
    entries[0].Value[0] = envGetMainThreadHandle();
    // ProcessHandle
    entries[1].Value[0] = g_procHandle;
    // OverrideHeap
    entries[3].Value[0] = nro_heap_start;
    entries[3].Value[1] = nro_heap_size;
    // Argv
    entries[4].Value[1] = (u64) &g_argv[0];
    // NextLoadPath
    entries[5].Value[0] = (u64) &g_nextNroPath[0];
    entries[5].Value[1] = (u64) &g_nextArgv[0];
    // LastLoadResult
    entries[6].Value[0] = g_lastRet;
    // RandomSeed
    entries[8].Value[0] = randomGet64();
    entries[8].Value[1] = randomGet64();
    // HosVersion
    entries[10].Value[0] = hosversionGet();

    u64 entrypoint = map_addr;

    g_nroAddr = map_addr;
    g_nroSize = nro_size;

    memset(__stack_top - STACK_SIZE, 0, STACK_SIZE);

    extern NORETURN void nroEntrypointTrampoline(u64 entries_ptr, u64 handle, u64 entrypoint);
    nroEntrypointTrampoline((u64) entries, -1, entrypoint);
}

int main(int argc, char **argv)
{   
    memcpy(g_savedTls, (u8*)armGetTls() + 0x100, 0x100);
    smExit(); // Close SM as we don't need it anymore.
    setupHbHeap();
    getOwnProcessHandle();
    loadNro();

    fatalThrow(MAKERESULT(Module_HomebrewLoader, 8));
    return 0;
}
