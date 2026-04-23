#ifndef PREFIX_EXTRACTOR_H
#define PREFIX_EXTRACTOR_H

// Extracts a gzipped tar into dest_dir. Returns 0 on success, -1 on error.
// The tarball is expected to have a single top-level "prefix/" directory;
// its contents are extracted directly into dest_dir (i.e. dest_dir/drive_c/...
// not dest_dir/prefix/drive_c/...).
int mythic_extract_prefix_tgz(const char *tgz_path, const char *dest_dir);

#endif
