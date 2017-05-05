#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <uchar.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <keyutils.h>
#include <libudev.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/mount.h>

#define BOOL bool
#include <tpm_tools/tpm_unseal.h>


// EFI GUID type
typedef struct {          
    uint32_t  a;
    uint16_t  b;
    uint16_t  c;
    uint8_t   d[8]; 
} EFI_GUID;

// EFI GUID for loader interface
static const EFI_GUID loader_guid = { 0x4a67b082, 0x0a4c, 0x41cf, { 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f } };

// path in the filesystem, where EFI variables are
static const char efivar_part[] = "/sys/firmware/efi/efivars";

// temporary mount point
#define MOUNT_POINT "/mnt"

// ESP is always vfat
#define FILE_SYSTEM "vfat"

// key name that system-cryptsetup will look for
#define KEYCTL_KEYNAME "cryptsetup"

// path to kernel commandline
#define COMMAND_LINE "/proc/cmdline"

// probably the real maximum is longer
#define MAX_COMMANDLINE 4096

/**
 * read one line (or length) from a given buffer
 */
static int read_one_line(const char* filename, char* buffer, size_t* length) {
    FILE* fp = fopen(filename, "r");
    if (!fp)
        return -errno;

    if (!fgets(buffer, *length, fp)) {
        if (ferror(fp))
            return  errno > 0 ? -errno : -EIO;
    }
    
    for (size_t i = 0; i < strlen(buffer); i++) {
        if (buffer[i] == '\n')
            buffer[i] ='\0';
    }

    fclose(fp);

    *length = strlen(buffer);
    return 0;
}

/**
 * parse the kernel commandline from procfs for a specific setting
 */
static bool parse_cmd(const char* keyname, char** option) {
    size_t len = MAX_COMMANDLINE;
    char buffer[len];

    if (read_one_line(COMMAND_LINE, buffer, &len) < 0) {
        return false;
    }
    
    size_t i, j;
    for (i = 0; i < len; i++) {
        if (buffer[i] == ' ')
            continue;
        if (strncmp(keyname, buffer + i, strlen(keyname)) == 0) {
            break;
        }
    }

    for (j = i + strlen(keyname); buffer[j] != ' ' && j < len; j++);

    *option = strndup(buffer + i + strlen(keyname) + 1, j - i - strlen(keyname) - 1);
    return true;
}

/**
 * Write a GUID type into a string
 */
static inline void efi_guid_to_string(const EFI_GUID* guid, char* guid_string) {
    snprintf(guid_string, 37, "%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
        guid->a, guid->b, guid->c, guid->d[0], guid->d[1], guid->d[2], guid->d[3], guid->d[4], guid->d[5], guid->d[6], guid->d[7]);
}

/**
 * Read a UTF-16 EFI variable into a string
 */
static bool efivar_read_var(const EFI_GUID* guid, const char* name, char* buffer, size_t* length) {
    // 36 is the length of a GUID
    // 2 is for one - and / and one \0 at the end
    size_t fname_length = strlen(efivar_part) + strlen(name) + 37 + 3;
    char filename[fname_length];
    char guid_string[37];

    efi_guid_to_string(guid, guid_string);
    snprintf(filename, fname_length, "%s/%s-%s", efivar_part, name, guid_string);

    FILE* fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "fopen '%s': %m\n", filename);
        return false;
    }

    char16_t char_buffer[*length];
    *length = fread(char_buffer, sizeof(char16_t), *length, fp);

    if (ferror(fp)) {
        fprintf(stderr, "fread '%s': %m\n", filename);
        fclose(fp);
        return false;
    }
    fclose(fp);

    mbstate_t state;
    memset(&state, 0, sizeof(state));

    size_t u8_len = 0;
    // skip type field, one uint32
    for (size_t i = 2; i < *length; i++) {
        ssize_t len = 0;
        len = c16rtomb(buffer + u8_len, char_buffer[i], &state);
        if (len == 0)
            continue;
        if (len > 0) {
            u8_len += len;
        } else
            break;
    }

    *length = u8_len;
    buffer[u8_len] = '\0';

    return true;
}

static bool find_device(struct udev* udev, const char* uuid, char* dev_name, size_t length) {
    bool ret = false;
    struct udev_enumerate* e = udev_enumerate_new(udev);
    if (!e) {
        fprintf(stderr, "Could not create udev_enumerate: %m\n");
        goto cleanup_udev;
    }

    udev_enumerate_add_match_subsystem(e, "block");
    udev_enumerate_add_match_property(e, "ID_PART_ENTRY_UUID", uuid);

    if (udev_enumerate_scan_devices(e) < 0) {
        fprintf(stderr, "Could not run udev_enumerate_scan: %m\n");
        goto cleanup_enum;
    }

    struct udev_list_entry* list = udev_enumerate_get_list_entry(e);
    struct udev_list_entry* le;
    const char* path = NULL;
    udev_list_entry_foreach(le, list) {
        if (path) {
            fprintf(stderr, "More than one matching partition in system\n");
            goto cleanup_enum;
        }
        path = udev_list_entry_get_name(le);
    }
    if (!path)
        goto cleanup_enum;
    struct udev_device* dev = udev_device_new_from_syspath(udev, path);
    if (!dev) {
        fprintf(stderr, "Could not get udev_device from /sys path: %m\n");
        goto cleanup_enum;
    }

    path = udev_device_get_devnode(dev);
    strncpy(dev_name, path, length);
    udev_device_unref(dev);
    ret = true;

cleanup_enum:
    udev_enumerate_unref(e);
cleanup_udev:
    return ret;
}

/**
 * Watch for device to appear
 */
static bool wait_for_device(const char* uuid, char* dev_name, size_t length) {
    struct pollfd fds[1];
    int pol;
    bool found = false;
    bool ret = false;

    struct udev* udev = udev_new();
    if (!udev) {
        fprintf(stderr, "Could not create udev handle: %m\n");
        return false;
    }

    struct udev_monitor* mon = udev_monitor_new_from_netlink(udev, "kernel");
    if (!mon) {
        fprintf(stderr, "Could not create udev_monitor handle: %m\n");
        goto cleanup_udev;
    }
    if (udev_monitor_enable_receiving(mon) < 0) {
        fprintf(stderr, "Could not enable udev_monitor reveiver: %m\n");
        goto cleanup_udev;
    }

    fds[0].events = POLLIN;
    fds[0].fd = udev_monitor_get_fd(mon);
    if (fds[0].fd < 0) {
        fprintf(stderr, "Could not get udev_monitor fd: %m\n");
        goto cleanup_mon;
    }
    
    while(!found) {
        struct udev_device* dev = udev_monitor_receive_device(mon);
        if (!dev) {
            //printf("Noting recieved\n");
            if (find_device(udev, uuid, dev_name, length)) {
                //printf("Found device, before poll: %s\n", dev_name);
                break;
            }
            pol = poll(fds, 1, 2);
            if (pol < 0) {
                fprintf(stderr, "Could not poll on udev_monitor: %m\n");
                goto cleanup_mon;
            }
            continue;
        }

        const char* subsystem = udev_device_get_property_value(dev, "SUBSYSTEM");
        if (!subsystem) {
            udev_device_unref(dev);
            //printf("Monitor: no subsystem.\n");
            continue;
        }
        if (strcmp(subsystem, "block") != 0) {
            udev_device_unref(dev);
            //printf("Monitor: %s\n", subsystem);
            continue;
        }

        const char* p_uuid = udev_device_get_property_value(dev, "ID_PART_ENTRY_UUID");
        if (!p_uuid)
            continue;
        if (strcmp(uuid, p_uuid) == 0) {
            strncpy(dev_name, udev_device_get_devnode(dev), length);
            found = true;
        }
        //printf("Monitor: %s\n", p_uuid);
        udev_device_unref(dev);
    }

    ret = true;
cleanup_mon:
    udev_monitor_unref(mon);
cleanup_udev:
    udev_unref(udev);
    return ret;
}

/**
 * Unseal key with TPM, store string in keyring
 */
static bool unseal_key(const char* keyfilename) {
    char filename[100];
    uint8_t* buf = NULL;
    int length = 0;
    int err;

    if (keyfilename[0] == '/')
        sprintf(filename, "%s%s", MOUNT_POINT, keyfilename);
    else
        sprintf(filename, "%s/%s", MOUNT_POINT, keyfilename);

    err = tpmUnsealFile(filename, &buf, &length, true);
    if (err != 0) {
        fprintf(stderr, "Could not unseal key from '%s': %s\n", filename, tpmUnsealStrerror(err));
        return false;
    }
    if (length >= 100) {
        fprintf(stderr, "Key is too long, systemd does not like that\n");
        free(buf);
        return false;
    }

    if (buf) {
        key_serial_t kid = add_key("user", KEYCTL_KEYNAME, buf, length, KEY_SPEC_USER_KEYRING);
        if (kid < 0) {
            fprintf(stderr, "Could not insert key in keyring: %m\n");
            free(buf);
            return false;
        }

        free(buf);
    }

    return true;
}

static void signal_abort(int sig) {
    if (umount2(MOUNT_POINT, MNT_DETACH) != 0) {
        fprintf(stderr, "Could not unmount ESP: %m\n");
    }
    exit(sig);
}

int main () {
    size_t len = 40;
    char uuid[len];
    char device[255];
    int ret = 1;

    char *keyfilename = NULL;
    parse_cmd("rd.tpm.key", &keyfilename);
    if (!keyfilename)
        return 0;

    if (!efivar_read_var(&loader_guid, "LoaderDevicePartUUID", uuid, &len)) {
        fprintf(stderr, "Could not read EFI variable\n");
        goto cleanup;
    }

    // udev always produces lowercase uuid filenames for GPT partitions
    for (size_t i = 0; i < len && uuid[i]; i++) {
        uuid[i] = tolower(uuid[i]);
    }

    bool wait = true;

    // no device yet, we need to wait
    if (wait) {
        if (!wait_for_device(uuid, device, sizeof(device))) {
            goto cleanup;
        }
    }

    if (mkdir(MOUNT_POINT, 0777) != 0) {
        int error = errno;
        // accept existing directory
        if (error != EEXIST) {
            fprintf(stderr, "Could not create mount point: '%s': %m\n", MOUNT_POINT);
            goto cleanup;
        }
    }
    
    if (mount(device, MOUNT_POINT, FILE_SYSTEM, MS_RDONLY, NULL) != 0) {
        fprintf(stderr, "Could not mount ESP: %m\n");
        goto cleanup;
    }

    // make sure we unmount
    signal(SIGABRT, &signal_abort);
    signal(SIGTERM, &signal_abort);

    printf("Using keyfile '%s'\n", keyfilename);
    if (unseal_key(keyfilename))
        ret = 0;

    if (umount2(MOUNT_POINT, MNT_DETACH) != 0) {
        fprintf(stderr, "Could not unmount ESP: %m\n");
    }

    // normal behaviour
    signal(SIGABRT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

cleanup:
    free(keyfilename);
    return ret;
}
