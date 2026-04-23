// Minimal gzip + ustar extractor. Handles the subset of tar produced by
// /usr/bin/tar on macOS: regular files (type '0'), directories (type '5'),
// and pax extended headers (type 'x', ignored).

#include "PrefixExtractor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <zlib.h>

#define BLOCK 512

static int parse_octal(const char *s, size_t n) {
    int v = 0;
    for (size_t i = 0; i < n && s[i]; i++) {
        if (s[i] == ' ' || s[i] == 0) continue;
        if (s[i] < '0' || s[i] > '7') return -1;
        v = (v << 3) | (s[i] - '0');
    }
    return v;
}

static int mkdir_p(const char *path) {
    char buf[1024];
    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(buf, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(buf, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

int mythic_extract_prefix_tgz(const char *tgz_path, const char *dest_dir) {
    gzFile gz = gzopen(tgz_path, "rb");
    if (!gz) {
        fprintf(stderr, "[prefix-extract] gzopen failed: %s\n", tgz_path);
        return -1;
    }

    if (mkdir_p(dest_dir) != 0) {
        fprintf(stderr, "[prefix-extract] mkdir_p dest failed: %s\n", dest_dir);
        gzclose(gz);
        return -1;
    }

    char header[BLOCK];
    char buf[BLOCK];
    int files = 0, dirs = 0;

    for (;;) {
        int n = gzread(gz, header, BLOCK);
        if (n == 0) break;
        if (n != BLOCK) {
            fprintf(stderr, "[prefix-extract] short header read: %d\n", n);
            gzclose(gz);
            return -1;
        }
        // End-of-archive: two zero blocks. Bail on any all-zero block.
        int all_zero = 1;
        for (int i = 0; i < BLOCK; i++) if (header[i]) { all_zero = 0; break; }
        if (all_zero) break;

        char name[101] = {0};
        memcpy(name, header, 100);
        int size = parse_octal(header + 124, 12);
        char type = header[156];

        // Strip leading "prefix/" so files land directly under dest_dir.
        const char *relname = name;
        if (strncmp(relname, "prefix/", 7) == 0) relname += 7;
        else if (strcmp(relname, "prefix") == 0) relname = "";

        char outpath[1200];
        if (*relname) {
            snprintf(outpath, sizeof(outpath), "%s/%s", dest_dir, relname);
        } else {
            snprintf(outpath, sizeof(outpath), "%s", dest_dir);
        }

        if (type == '5' || (type == 0 && name[strlen(name) - 1] == '/')) {
            // Directory
            if (*relname) {
                if (mkdir_p(outpath) != 0) {
                    fprintf(stderr, "[prefix-extract] mkdir %s: %s\n", outpath, strerror(errno));
                    gzclose(gz);
                    return -1;
                }
                dirs++;
            }
        } else if (type == '0' || type == 0) {
            // Regular file — ensure parent dir, then write size bytes
            char parent[1200];
            strncpy(parent, outpath, sizeof(parent) - 1);
            parent[sizeof(parent) - 1] = 0;
            char *slash = strrchr(parent, '/');
            if (slash) { *slash = 0; mkdir_p(parent); }

            int fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                fprintf(stderr, "[prefix-extract] open %s: %s\n", outpath, strerror(errno));
                gzclose(gz);
                return -1;
            }
            int remaining = size;
            while (remaining > 0) {
                int want = remaining < BLOCK ? remaining : BLOCK;
                int got = gzread(gz, buf, BLOCK);
                if (got != BLOCK) {
                    fprintf(stderr, "[prefix-extract] short data read for %s\n", relname);
                    close(fd);
                    gzclose(gz);
                    return -1;
                }
                if (write(fd, buf, want) != want) {
                    fprintf(stderr, "[prefix-extract] write %s: %s\n", outpath, strerror(errno));
                    close(fd);
                    gzclose(gz);
                    return -1;
                }
                remaining -= want;
            }
            close(fd);
            files++;
        } else if (type == 'x' || type == 'g' || type == 'L' || type == 'K') {
            // pax extended / GNU long-name headers — skip payload
            int pad = (size + BLOCK - 1) / BLOCK * BLOCK;
            while (pad > 0) {
                if (gzread(gz, buf, BLOCK) != BLOCK) {
                    fprintf(stderr, "[prefix-extract] short ext-header skip\n");
                    gzclose(gz);
                    return -1;
                }
                pad -= BLOCK;
            }
        } else {
            // Unknown type — skip its data blocks
            int pad = (size + BLOCK - 1) / BLOCK * BLOCK;
            while (pad > 0) {
                if (gzread(gz, buf, BLOCK) != BLOCK) break;
                pad -= BLOCK;
            }
        }
    }

    gzclose(gz);
    fprintf(stderr, "[prefix-extract] extracted %d files, %d dirs to %s\n", files, dirs, dest_dir);
    return 0;
}
