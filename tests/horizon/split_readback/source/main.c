#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <switch.h>

#ifndef SPLIT_PATH
#error SPLIT_PATH must name the transferred canonical directory
#endif
#ifndef EXPECTED_SIZE
#error EXPECTED_SIZE must match the original source length
#endif
#ifndef EXPECTED_SHA256
#error EXPECTED_SHA256 must match the original source SHA-256
#endif

#if MBEDTLS_VERSION_MAJOR >= 3
#define SHA256_START mbedtls_sha256_starts
#define SHA256_UPDATE mbedtls_sha256_update
#define SHA256_FINISH mbedtls_sha256_finish
#else
#define SHA256_START mbedtls_sha256_starts_ret
#define SHA256_UPDATE mbedtls_sha256_update_ret
#define SHA256_FINISH mbedtls_sha256_finish_ret
#endif

#define READ_BUFFER_SIZE (1024 * 1024)

static int read_and_check_split(void) {
    FsFileSystem filesystem = {0};
    FsFile file = {0};
    bool filesystem_open = false;
    bool file_open = false;
    FsDirEntryType entry_type;
    mbedtls_sha256_context hash;
    unsigned char buffer[READ_BUFFER_SIZE];
    unsigned char digest[32];
    char digest_hex[65];
    u64 file_size = 0;
    u64 offset = 0;
    Result result;
    int status = 1;

    mbedtls_sha256_init(&hash);
    result = fsOpenSdCardFileSystem(&filesystem);
    if (R_FAILED(result)) {
        printf("INTEROP_FAIL reason=sd_filesystem_open result=%08" PRIx32 "\n", result);
        goto cleanup;
    }
    filesystem_open = true;

    result = fsFsGetEntryType(&filesystem, SPLIT_PATH, &entry_type);
    if (R_FAILED(result)) {
        printf("INTEROP_FAIL reason=entry_type result=%08" PRIx32 "\n", result);
        goto cleanup;
    }
    if (entry_type != FsDirEntryType_File) {
        printf("INTEROP_FAIL reason=not_a_logical_file\n");
        goto cleanup;
    }

    result = fsFsOpenFile(&filesystem, SPLIT_PATH, FsOpenMode_Read, &file);
    if (R_FAILED(result)) {
        printf("INTEROP_FAIL reason=logical_file_open result=%08" PRIx32 "\n", result);
        goto cleanup;
    }
    file_open = true;

    result = fsFileGetSize(&file, &file_size);
    if (R_FAILED(result)) {
        printf("INTEROP_FAIL reason=file_size result=%08" PRIx32 "\n", result);
        goto cleanup;
    }
    if (file_size != (u64)EXPECTED_SIZE) {
        printf("INTEROP_FAIL reason=size_mismatch expected=%" PRIu64 " actual=%" PRIu64 "\n",
               (u64)EXPECTED_SIZE, file_size);
        goto cleanup;
    }

    if (SHA256_START(&hash, 0) != 0) {
        printf("INTEROP_FAIL reason=sha256_start\n");
        goto cleanup;
    }
    while (offset < file_size) {
        const u64 remaining = file_size - offset;
        const u64 requested = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        u64 bytes_read = 0;
        result = fsFileRead(&file, (s64)offset, buffer, requested, FsReadOption_None, &bytes_read);
        if (R_FAILED(result) || bytes_read == 0 || bytes_read > requested) {
            printf("INTEROP_FAIL reason=short_read offset=%" PRIu64 " result=%08" PRIx32 "\n",
                   offset, result);
            goto cleanup;
        }
        if (SHA256_UPDATE(&hash, buffer, (size_t)bytes_read) != 0) {
            printf("INTEROP_FAIL reason=sha256_update\n");
            goto cleanup;
        }
        offset += bytes_read;
    }

    if (SHA256_FINISH(&hash, digest) != 0) {
        printf("INTEROP_FAIL reason=sha256_finish\n");
        goto cleanup;
    }
    for (size_t index = 0; index < sizeof(digest); index++) {
        (void)snprintf(&digest_hex[index * 2], 3, "%02x", digest[index]);
    }
    digest_hex[64] = '\0';
    if (strlen(EXPECTED_SHA256) != 64 || strcmp(digest_hex, EXPECTED_SHA256) != 0) {
        printf("INTEROP_FAIL reason=sha256_mismatch expected=%s actual=%s\n",
               EXPECTED_SHA256, digest_hex);
        goto cleanup;
    }

    printf("INTEROP_PASS bytes=%" PRIu64 " sha256=%s path=%s\n",
           file_size, digest_hex, SPLIT_PATH);
    status = 0;

cleanup:
    if (file_open) {
        fsFileClose(&file);
    }
    if (filesystem_open) {
        fsFsClose(&filesystem);
    }
    mbedtls_sha256_free(&hash);
    return status;
}

int main(void) {
    int status;
    consoleInit(NULL);
    printf("Read-only Horizon Split-file check\n");
    printf("Path: %s\nExpected bytes: %" PRIu64 "\n", SPLIT_PATH, (u64)EXPECTED_SIZE);
    consoleUpdate(NULL);
    status = read_and_check_split();
    printf("\n%s\nPress + to close this screen.\n",
           status == 0 ? "HORIZON_READBACK=PASS" : "HORIZON_READBACK=FAIL");
    consoleUpdate(NULL);
    while (appletMainLoop()) {
        hidScanInput();
        if (hidKeysDown(CONTROLLER_P1_AUTO) & KEY_PLUS) {
            break;
        }
        svcSleepThread(100000000ULL);
    }
    consoleExit(NULL);
    return status;
}
