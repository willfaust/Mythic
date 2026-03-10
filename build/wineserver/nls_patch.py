import re

with open('/tmp/wine-ios-server/unicode_ios.c', 'r') as f:
    content = f.read()

# Replace the get_nls_dir function body
old = '''static char *get_nls_dir(void)
{
    char *p, *dir, *ret;

#if defined(__linux__) || defined(__FreeBSD_kernel__) || defined(__NetBSD__)
    dir = realpath( "/proc/self/exe", NULL );
#elif defined (__FreeBSD__) || defined(__DragonFly__)
    static int pathname[] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
    size_t dir_size = PATH_MAX;
    dir = malloc( dir_size );
    if (dir)
    {
        if (sysctl( pathname, ARRAY_SIZE( pathname ), dir, &dir_size, NULL, 0 ))
        {
            free( dir );
            dir = NULL;
        }
    }
#elif defined(__APPLE__)
    uint32_t dir_size = PATH_MAX;
    dir = malloc( dir_size );
    if (dir)
    {
        if (_NSGetExecutablePath( dir, &dir_size ))
        {
            free( dir );
            dir = NULL;
        }
    }
#else
    dir = realpath( server_argv0, NULL );
#endif
    if (!dir) return NULL;
    if (!(p = strrchr( dir, '/' )))
    {
        free( dir );
        return NULL;
    }
    *(++p) = 0;
    if (p > dir + 8 && !strcmp( p - 8, "/server/" ))  /* inside build tree */
    {
        strcpy( p - 8, "/nls" );
        return dir;
    }
    ret = build_relative_path( dir, BINDIR, DATADIR "/wine/nls" );
    free( dir );
    return ret;
}'''

new = '''static char *get_nls_dir(void)
{
    /* iOS: look for NLS files inside the app bundle */
    char *p, *dir;
    uint32_t dir_size = PATH_MAX;
    dir = malloc( dir_size );
    if (!dir) return NULL;
    if (_NSGetExecutablePath( dir, &dir_size ))
    {
        free( dir );
        return NULL;
    }
    if (!(p = strrchr( dir, '/' )))
    {
        free( dir );
        return NULL;
    }
    *(++p) = 0;
    /* Append "nls" to the bundle directory */
    strcat( dir, "nls" );
    return dir;
}'''

content = content.replace(old, new)

with open('/tmp/wine-ios-server/unicode_ios.c', 'w') as f:
    f.write(content)

print("Patched successfully")
