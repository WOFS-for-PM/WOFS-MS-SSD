#include "usyscall.h"

#include "./utils/xxhash.h"

#define FD_CACHE_BITS 12  // 2 ^ 12 = 4096 = log2(USYS_MAX_FD)

extern struct super_operations hk_sops;
extern struct super_block sb;

// key: name, value: struct file
struct fd_cache {
    spinlock_t locks[1 << FD_CACHE_BITS];
    DECLARE_HASHTABLE(cache, FD_CACHE_BITS);
};

static struct {
    struct file *fdt[USYS_MAX_FD];
    struct dentry *cwd;
    struct fd_cache fd_cache;
} CURRENT;

struct usys_open_frame {
    // starting inode. Ignored if path starts with '/'
    struct dentry *start;
    // string of the path
    const char *path;
    // the target's inode returned
    struct dentry *current;
    // target's parent inode returned
    struct dentry *parent;
    // the mode provided for last level if request for create
    mode_t i_mode;
    // flags. Both in and out.
    uint16_t flags;
};

static int __fd_add(struct fd_cache *cache, const char *name,
                    struct file *file) {
    int slot = hash_min(XXH32(name, strlen(name), 0), FD_CACHE_BITS);

    spin_lock(&cache->locks[slot]);
    hlist_add_head(&file->f_path.dentry->d_hash, &cache->cache[slot]);
    spin_unlock(&cache->locks[slot]);

    return 0;
}

static int __fd_remove(struct fd_cache *cache, const char *name,
                       struct file *file) {
    int slot = hash_min(XXH32(name, strlen(name), 0), FD_CACHE_BITS);

    spin_lock(&cache->locks[slot]);
    hash_del(&file->f_path.dentry->d_hash);
    spin_unlock(&cache->locks[slot]);

    return 0;
}

static char *__getname(const char **cursor) {
    const char *start = *cursor;
    char *name;
    int len;

    while (**cursor != '/' && **cursor != '\0')
        (*cursor)++;

    len = *cursor - start;
    name = kmalloc(len + 1, GFP_KERNEL);
    memcpy(name, start, len);
    name[len] = '\0';

    return name;
}

// return how many names to be resolved
static int __calcname(const char *cursor) {
    int count = 0;

    while (*cursor != '\0') {
        if (*cursor == '/' && *(cursor + 1) != '\0') {
            cursor++;
        } else {
            count++;
            while (*cursor != '/' && *cursor != '\0') {
                cursor++;
            }
        }
    }

    return count;
}

static char *__putname(char *name) {
    kfree(name);
    return NULL;
}

static struct dentry *__d_get(struct dentry *dir_dentry,
                              const unsigned char *name, int *found) {
    struct dentry *dentry;
    struct list_head *pos;

    *found = 0;

    list_for_each(pos, &dir_dentry->d_subdirs) {
        dentry = list_entry(pos, struct dentry, d_child);
        if (!strcmp((const char *)dentry->d_name.name, (const char *)name)) {
            *found = 1;
            return dentry;
        }
    }

    dentry = d_alloc(dir_dentry,
                     &(struct qstr)QSTR_INIT(name, strlen((const char *)name)));

    dentry->d_sb = dir_dentry->d_sb;
    list_add_tail(&dentry->d_child, &dir_dentry->d_subdirs);

    return dentry;
}

static void __d_put(struct dentry *dentry) {
    struct list_head *pos, *n;
    struct dentry *sub_dentry;

    list_for_each_safe(pos, n, &dentry->d_subdirs) {
        sub_dentry = list_entry(pos, struct dentry, d_child);
        assert(sub_dentry->d_inode == NULL);
        __d_put(sub_dentry);
    }

    assert(list_empty(&dentry->d_subdirs));

    __putname((char *)dentry->d_name.name);

    list_del(&dentry->d_child);

    dput(dentry);
}

int do_usys_open(const char *pathname, int flags,
                 struct usys_open_frame *frame) {
    const char *cursor = pathname;
    struct dentry *dirent, *sub_dirent, *alias;
    struct inode *dir;
    char *name;
    int ret = 0, hit, names_to_resolve;

    if (cursor[0] == '/') {
        dirent = sb.s_root;
    } else {
        assert(frame->start != NULL);
        dirent = frame->start;
    }

    while (*cursor == '/')
        cursor++;

    dirent->d_inode->i_atime = current_time(dirent->d_inode);

    if (*cursor == '\0') {
        // request is root
        frame->current = dirent;
        return 0;
    }

    /* loop over each directory in the path */
    while (1) {
        if (*cursor == '\0') {
            // request is the last level
            frame->current = dirent;
            break;
        }

        name = __getname(&cursor);

        dir = dirent->d_inode;

        if ((dir->i_mode & S_IFMT) != S_IFDIR) {
            ret = -ENOTDIR;
            goto out;
        }

        if ((dir->i_mode & S_IXUSR) == 0) {
            ret = -ENOEXEC;
            goto out;
        }

        frame->parent = dirent;
        sub_dirent = __d_get(dirent, (const unsigned char *)name, &hit);
        if (!hit) {
            assert(dir->i_op->lookup);
            alias = dir->i_op->lookup(dir, sub_dirent, 0);
            if (alias != NULL) {
                sub_dirent = alias;
                __d_put(sub_dirent);
            }

            if (sub_dirent->d_inode == NULL) {
                names_to_resolve = __calcname(cursor);

                if (names_to_resolve > 1) {
                    ret = -ENOENT;
                    goto out;
                }

                if (flags & O_CREAT) {
                    // Create One
                    assert(dir->i_op->create);
                    assert(dir->i_sb);
                    ret = dir->i_op->create(dir, sub_dirent, frame->i_mode,
                                            flags & O_EXCL);
                    if (ret)
                        return ret;
                } else {
                    __d_put(sub_dirent);
                    ret = -ENOENT;
                    goto out;
                }
            }
        }
        dirent = sub_dirent;

        dirent->d_inode->i_atime = current_time(dirent->d_inode);
    }

out:
    return ret;
}

long do_sys_ftruncate(unsigned int fd, loff_t length, int small) {
    struct file *file = CURRENT.fdt[fd];
    struct inode *inode = file->f_inode;
    struct iattr newattrs;
    int ret;

    if (length < 0)
        return -EINVAL;

    newattrs.ia_size = length;
    newattrs.ia_valid = ATTR_SIZE;

    inode_lock(inode);

    ret = inode->i_op->setattr(file->f_path.dentry, &newattrs);

    inode_unlock(inode);

    return ret;
}
// ================== usyscall ==================
int usys_open(const char *pathname, int flags, int mode) {
    pr_debug("usys_open(%s)\n", pathname);

    int fd, ret;
    struct file *file;
    struct usys_open_frame frame = {.flags = flags, .path = pathname};

    if (flags & O_CREAT) {
        frame.flags |= O_CREAT;
        frame.i_mode = mode | S_IFREG;
    }

    if (*pathname != '/') {
        if (CURRENT.cwd == NULL) {
            CURRENT.cwd = sb.s_root;
        }
        // start from the current dir
        frame.start = CURRENT.cwd;
    }

    for (fd = 0; fd < USYS_MAX_FD; fd++) {
        if (CURRENT.fdt[fd] == NULL) {
            break;
        }
    }

    if (fd == USYS_MAX_FD) {
        return -1;
    }

    if ((ret = do_usys_open(pathname, flags, &frame)) < 0) {
        return ret;
    }

    file = alloc_file(
        &(struct path){
            .dentry = frame.current,
            .mnt = NULL,
        },
        flags, frame.current->d_inode->i_fop);
    file->private_data = kmalloc(strlen(pathname) + 1, GFP_KERNEL);
    // private_data as the pathname
    strcpy(file->private_data, pathname);
    assert(file->f_op);

    CURRENT.fdt[fd] = file;

    __fd_add(&CURRENT.fd_cache, pathname, CURRENT.fdt[fd]);

    return ret;
}

int usys_close(int fd) {
    pr_debug("usys_close(%d)\n", fd);

    struct file *file = CURRENT.fdt[fd];

    assert(file->f_inode != NULL);
    assert(file->private_data != NULL);
    __fd_remove(&CURRENT.fd_cache, file->private_data, file);

    iput(file->f_inode);
    file->f_inode = NULL;
    __d_put(file->f_path.dentry);
    file->f_path.dentry = NULL;
    file->f_op = NULL;
    file->f_pos = 0;
    fput(file);

    CURRENT.fdt[fd] = NULL;
    return 0;
}

ssize_t usys_read(int fd, void *buf, size_t count) {
    pr_debug("usys_read(%d, %p, %lu)\n", fd, buf, count);

    struct file *file = CURRENT.fdt[fd];
    ssize_t ret;

    assert(file->f_op);
    assert(file->f_op->read);
    ret = file->f_op->read(file, buf, count, &file->f_pos);

    return ret;
}

ssize_t usys_write(int fd, const void *buf, size_t count) {
    pr_debug("usys_write(%d, %p, %lu)\n", fd, buf, count);

    struct file *file = CURRENT.fdt[fd];
    ssize_t ret;

    assert(file->f_op);
    assert(file->f_op->write);
    ret = file->f_op->write(file, buf, count, &file->f_pos);

    return ret;
}

int usys_lseek(int fd, long offset, int whence) {
    struct file *file = CURRENT.fdt[fd];
    int ret;

    if (file->f_inode->i_fop->llseek) {
        ret = file->f_inode->i_fop->llseek(file, offset, whence);
    } else {
        ret = generic_file_llseek(file, offset, whence);
    }

    return ret;
}

int usys_fsync(int fd) {
    struct file *file = CURRENT.fdt[fd];
    int ret;

    if (file->f_op->fsync) {
        ret = file->f_op->fsync(file, 0, file->f_inode->i_size, 1);
    } else {
        ret = 0;
    }

    return ret;
}

int usys_ftruncate(int fd, off_t len) {
    return do_sys_ftruncate(fd, len, 1);
}

int usys_init(void) {
    memset(CURRENT.fdt, 0, sizeof(CURRENT.fdt));

    hash_init(CURRENT.fd_cache.cache);
    for (int i = 0; i < (1 << FD_CACHE_BITS); i++) {
        spin_lock_init(&CURRENT.fd_cache.locks[i]);
    }

    CURRENT.cwd = sb.s_root;

    return 0;
}