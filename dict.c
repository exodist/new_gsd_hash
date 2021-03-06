#include "dict.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define DEFAULT_TABLE_MULTIPLIER 4
#define DEFAULT_STORE_MULTIPLIER 2

typedef struct node  node;
typedef struct store store;

typedef void* kv;

struct node {
    size_t hash;

    kv key;
    kv val;

    node *left;
    node *right;
};

struct store {
    dict *d;

    size_t index;
    size_t free_count;

    store *next;
    node  *free;

    store *left;
    store *right;

    node nodes[];
};

struct dict {
    size_t base;

    size_t store_count; // 2 x base
    size_t table_count; // 4 x base

    size_t store_size;  // 2 x base x sizeof(node)
    size_t table_size;  // 4 x base x sizeof(node *)

    store *curr_store; // points at root store until full, then next store
    store *root_store; // points into data section
    node **hash_table; // points into data section

    size_t  active[2];      // Count of in-progress calls
    node   *dead_nodes[2];  // List of nodes to return
    store  *dead_stores[2]; // List of stores to free
    int8_t  epoch;          // Current epoch (0 or 1)

    uint8_t data[];
};

//#########################################################################

node BLOCK;

//#########################################################################

kv find_node(dict *d, size_t hash, kv key, node ***branch, node **found);
node **locate_node(dict *d, node *n);
size_t find_branch(node *from, size_t hash, kv key, node ***branch);

int compare_node(node *n, size_t hash, kv key, kv *val);

node *alloc_node(dict *d, uintptr_t ptr);

void unalloc_node(dict *d, node *n);

void dispose_node(dict *d, node *n);

int  join_epoch(dict *d);
void leave_epoch(dict *d, int epoch);

//#########################################################################

void *atomic_read_kv (kv *ptr);
void  atomic_write_kv(kv *ptr, kv val);
int   atomic_swap_kv (kv *ptr, kv *old, kv new);

node *atomic_read_node (node **ptr);
void  atomic_write_node(node **ptr, node *val);
int   atomic_swap_node (node **ptr, node **old, node *new);

//#########################################################################

dict *dict_create(size_t base) {
    size_t store_count = DEFAULT_STORE_MULTIPLIER * base;
    size_t table_count = DEFAULT_TABLE_MULTIPLIER * base;

    size_t store_size = (store_count * sizeof(node)) - sizeof(node);
    size_t table_size = (table_count * sizeof(node *));

    size_t d_size = sizeof(dict) + store_size + table_size - sizeof(uint8_t);

    dict *d = malloc(d_size);
    if (!d) return NULL;
    memset(&(d->data), 0, table_size + store_size);

    d->base = base;
    d->store_count = store_count;
    d->table_count = table_count;
    d->store_size  = store_size;
    d->table_size  = table_size;

    d->hash_table = (node **)&(d->data);
    d->root_store = (store *)&(d->data[table_size]);
    d->curr_store = d->root_store;

    d->root_store->d = d;

    return d;
}

void dict_free(dict *d) {
    __atomic_store_n(&(d->epoch), -1, __ATOMIC_SEQ_CST);

    while(__atomic_load_n(d->active + 0, __ATOMIC_CONSUME) || __atomic_load_n(d->active + 1, __ATOMIC_CONSUME)) {
        // wait...
    }

    store *s = d->root_store;
    while (s) {
        store *kill = s;
        s = s->next;
        if (s != d->root_store) free(kill);
    }
    free(d);
}

void *dict_insert(dict *d, uint64_t hash, void *key, void *val) {
    assert(val);
    node *new     = NULL;
    node *found   = NULL;
    node **branch = NULL;

    int e = join_epoch(d);

    while (1) {
        kv cval = find_node(d, hash, key, &branch, &found);
        if (cval) {
            if (new) unalloc_node(d, new);
            leave_epoch(d, e);
            return cval;
        }

        if (!new) {
            new = alloc_node(d, (uintptr_t)branch);
            if (!new) {
                leave_epoch(d, e);
                return NULL;
            }
            new->key  = key;
            new->val  = val;
            new->hash = hash;
        }

        if (atomic_swap_node(branch, NULL, new)) {
            leave_epoch(d, e);
            return val;
        }
    }

    leave_epoch(d, e);
}

void *dict_update(dict *d, uint64_t hash, void *key, void *oldval, void *newval) {
    assert(oldval);
    assert(newval);
    node *found   = NULL;

    int e = join_epoch(d);

    kv cval = find_node(d, hash, key, NULL, &found);

    if (!cval) {
        leave_epoch(d, e);
        return NULL;
    }

    if (cval != oldval) {
        leave_epoch(d, e);
        return NULL;
    }

    atomic_swap_kv(&(found->val), &cval, newval);
    leave_epoch(d, e);
    return cval; // This should have been updated by atomic_swap_kv to have the correct value.
}

void *dict_check(dict *d, uint64_t hash, void *key) {
    int e = join_epoch(d);
    kv cval = find_node(d, hash, key, NULL, NULL);
    leave_epoch(d, e);
    return cval;
}

void *dict_set(dict *d, uint64_t hash, void *key, void *newval) {
    assert(newval);

    while (1) {
        int e = join_epoch(d);
        void *cval = dict_insert(d, hash, key, newval);
        leave_epoch(d, e);
        if (cval == newval) return cval;
        if (cval == NULL)   return NULL;

        e = join_epoch(d);
        cval = dict_update(d, hash, key, cval, newval);
        leave_epoch(d, e);
        if (cval == newval) return cval;
    }
}

void *dict_remove(dict *d, uint64_t hash, void *key, void *oldval) {
    kv cval = NULL;

    node *found   = NULL;
    node **branch = NULL;

    int e = join_epoch(d);
    cval = find_node(d, hash, key, &branch, &found);

    if (!cval) {
        leave_epoch(d, e);
        return NULL;
    }

    if (cval != oldval) {
        leave_epoch(d, e);
        return cval;
    }

    if(!atomic_swap_kv(&(found->val), &cval, NULL)) {
        leave_epoch(d, e);
        return cval; // updated to most recent value in the failed swap
    }

    // Fix the tree
    while(1) {
        node *us = found;
        branch   = locate_node(d, us); // Refresh branch

        node *left  = NULL;
        node *right = NULL;

        // Block branches if they are NULL, otherwise shove them into the
        // left/right vars declared above.
        atomic_swap_node(&(us->left),  &left,  &BLOCK);
        atomic_swap_node(&(us->right), &right, &BLOCK);

        if (left == &BLOCK && right == &BLOCK) {
            if (atomic_swap_node(branch, &us, NULL)) break;
            continue;
        }

        // If we have one empty, and one populated, wrangle them into the
        // correct pointers so we don't copy and paste logic.
        node **parent = NULL;
        node  *child  = NULL;
        if (left == &BLOCK) {
            parent = &(us->right);
            child  = left;
        }
        else if (right == &BLOCK) {
            parent = &(us->left);
            child  = right;
        }

        // Block the path, do the swap, unblock if swap fails
        // but only if we have one free and one populated, otherwise keep going.
        if (parent && child) {
            if(!atomic_swap_node(parent, &child, &BLOCK)) continue; // Awe shucks
            if(atomic_swap_node(branch, &us, child))      break;    // Yay!
            atomic_write_node(parent, child); // Be Kind ReWind (nothing else can unblock it but us)
            continue;
        }

        // Both branches have nodes, now it is complicated...
        // Find best strategy (left into right or right into left)

        // Get some objects to work with
        size_t rhash = __atomic_load_n(&(right->hash), __ATOMIC_CONSUME);
        size_t lhash = __atomic_load_n(&(left->hash),  __ATOMIC_CONSUME);
        kv rkey = atomic_read_kv(&(right->key));
        kv lkey = atomic_read_kv(&(left->key));

        // Child node deleted, retry.
        if (!rkey || !lkey) continue;

        // Map out both paths
        node **lbranch = NULL;
        node **rbranch = NULL;
        size_t ldepth = find_branch(left,  rhash, rkey, &lbranch);
        size_t rdepth = find_branch(right, lhash, lkey, &rbranch);

        // Pick the short path
        node **prune = NULL;
        if (ldepth >= rdepth) {
            prune  = &(us->left);
            parent = rbranch;
            child  = left;
        }
        else {
            prune  = &(us->right);
            parent = lbranch;
            child  = right;
        }

        // Reserve the short path
        if(!atomic_swap_node(parent, NULL, &BLOCK)) continue;
        // Block the path we are moving
        if(!atomic_swap_node(prune, &child, &BLOCK)) {
            // Ooops, start over :-(
            atomic_write_node(parent, NULL); // Be Kind ReWind
            continue;
        }

        // Success! use our reservation
        atomic_write_node(parent, child);

        // Loop again now that we have just a left or right branch (reuse the existing logic).
    }

    // put node in garbage
    dispose_node(d, found);

    leave_epoch(d, e);
    return cval;
}

//#########################################################################

kv find_node(dict *d, size_t hash, kv key, node ***branch, node **found) {
    // Find the table entry
    size_t table_idx = hash % d->table_count;
    node **table_slot = d->hash_table + table_idx;

    // Empty slot
    node **link = table_slot;
    node *curr = atomic_read_node(link);

    while(curr) {
        kv val = NULL;

        // start over if we got blocked.
        if (curr == &BLOCK) {
            link = table_slot;
            curr = atomic_read_node(link);
        }

        int dir = compare_node(curr, hash, key, &val);
        switch(dir) {
            case 0:
                *branch = link;
                *found  = curr;
            return val;

            case -1:
            case -2:
                link = &(curr->left);
            break;

            case 1:
                link = &(curr->right);
            break;

            default: assert(dir >= -2 && dir <= 1);
        };

        curr = atomic_read_node(link);
    }

    *branch = link;
    *found = NULL;
    return NULL;
}

int compare_node(node *n, size_t hash, kv key, kv *val) {
    // Key and hash do not change until a node is ready to be recycled, if that
    // happens val will be NULL and we will use that as our final check.

    *val = NULL;

    size_t nhash = n->hash;
    if (hash > nhash) return  1;
    if (hash < nhash) return -1;

    // Same hash!
    kv nkey = n->key;
    if (key > nkey) return  1;
    if (key < nkey) return -1;

    // Same key!
    kv v = atomic_read_kv(&(n->val));
    if (v == NULL) return -2; // Deleted, keep looking, go left

    if (val) *val = v;
    return 0; // Node match, val is not NULL
}

node **locate_node(dict *d, node *n) {
    size_t table_idx = n->hash % d->table_count;
    node **table_slot = d->hash_table + table_idx;
    node **link = table_slot;
    node  *curr = atomic_read_node(link);

    while(curr) {
        if (curr == n) return link;

        if (curr == &BLOCK) {
            link = table_slot;
            curr = atomic_read_node(link);
            continue;
        }

        int dir = compare_node(curr, n->hash, n->key, NULL);
        switch(dir) {
            case -1:
            case -2:
                link = &(curr->left);
            break;

            case 1:
                link = &(curr->right);
            break;

            default: assert(dir && dir >= -2 && dir <= 1);
        };

        curr = atomic_read_node(link);
    }

    return NULL;
}

/*
struct node {
    size_t hash;

    kv key;
    kv val;

    node *left;
    node *right;
};

struct store {
    dict *d;

    size_t index;
    size_t free_count;

    store *next;
    node  *free;

    store *left;
    store *right;

    node nodes[];
};

struct dict {
    size_t base;

    size_t store_count; // 2 x base
    size_t table_count; // 4 x base

    size_t store_size;  // 2 x base x sizeof(node)
    size_t table_size;  // 4 x base x sizeof(node *)

    store *curr_store; // points at root store until full, then next store
    store *root_store; // points into data section
    node  *hash_table; // points into data section

    size_t  active[2];      // Count of in-progress calls
    node   *dead_nodes[2];  // List of nodes to return
    store  *dead_stores[2]; // List of stores to free
    int8_t  epoch;          // Current epoch (0 or 1)

    uint8_t data[];
};

 */


size_t find_branch(node *from, size_t hash, kv key, node ***branch) {
    size_t depth = 0;
    node *curr = from;

    while (curr) {
        depth++;

        int dir = compare_node(from, hash, key, NULL);
        switch(dir) {
            case -1:
            case -2:
                *branch = &(curr->left);
            break;

            case 1:
                *branch = &(curr->right);
            break;

            default: assert(dir && dir >= -2 && dir <= 1);
        };

        curr = atomic_read_node(*branch);
    }

    return depth;
}

node *alloc_node(dict *d, uintptr_t ptr);

void unalloc_node(dict *d, node *n);

void dispose_node(dict *d, node *n);

int  join_epoch(dict *d);
void leave_epoch(dict *d, int epoch);

//#########################################################################

kv atomic_read_kv(kv *ptr) {
    kv out = NULL;
    __atomic_load(ptr, &out, __ATOMIC_CONSUME);
    return out;
}

void atomic_write_kv(kv *ptr, kv val) {
    __atomic_store(ptr, &val, __ATOMIC_RELEASE);
}

int atomic_swap_kv(kv *ptr, kv *old, kv new) {
    // Shortcut for swap from NULL
    kv x;
    if (old == NULL) {
        x = NULL;
        old = &x;
    }

    return __atomic_compare_exchange(
        ptr,
        old,
        &new,
        0,
        __ATOMIC_ACQ_REL,
        __ATOMIC_CONSUME
    );
}

node *atomic_read_node(node **ptr) {
    node *out = NULL;
    __atomic_load(ptr, &out, __ATOMIC_CONSUME);
    return out;
}

void atomic_write_node(node **ptr, node *val) {
    __atomic_store(ptr, &val, __ATOMIC_RELEASE);
}

int atomic_swap_node(node **ptr, node **old, node *new) {
    // Shortcut for swap from NULL
    node *x;
    if (old == NULL) {
        x = NULL;
        old = &x;
    }

    return __atomic_compare_exchange(
        ptr,
        old,
        &new,
        0,
        __ATOMIC_ACQ_REL,
        __ATOMIC_CONSUME
    );
}


//#########################################################################
//#########################################################################
//#########################################################################
//#########################################################################












/*

// store utils
inline size_t store_size(size_t base, int root);
inline int address_in_store(uintptr_t addr, uintptr_t s, size_t base, int root);
inline int is_root_node(node *n, store *root, size_t base);

node *grab_next(store *s, size_t base);
node *grab_free(store *s);
store *find_store(dict *d, void *want, store **parent, int *dir);

// Node allocation
node *alloc_node(dict *d, void *key, node *root, node *parent);
void  unalloc_node(dict *d, node *n);

// Node locations
node *find_root_node(store *root_store, uint64_t hash);
node *find_node(node *root, uint64_t hash, void *key, node **parent);

// Node management
void *update_node(node *n, void *old, void *new); // Atomic swap, allow NULL
void *insert_node(node *nearest, node *new);      // Atomic insert, loop with a search+update on nearest
void *remove_node(node *n, node *parent);         // Note: Assert key set to NULL already

//#########################################################################

inline size_t store_size(size_t base, int root) {
    size_t out   = sizeof(store);
    size_t nsize = sizeof(node);
    return (out - nsize) + (base * nsize * (root ? 6 : 2));
}

inline int address_in_store(uintptr_t addr, uintptr_t s, size_t base, int root) {
    uintptr_t end = s + store_size(base, root);
    if (addr > end || addr < s) return 0;
    return 1;
}

inline int is_root_node(node *n, store *root, size_t base) {
    if (!address_in_store((uintptr_t)n, (uintptr_t)root), base, 1) return 0;
    uintptr_t end = (uintptr_t)root + store_size(base, 0);
    if ((uintptr_t)n >= end) return 1;
    return 0;
}

node *grab_free(store *s) {
    while(1) {
        node *new = s->free;
        if (!new) return NULL;

        s->free = new->key; // TODO atomic || try again
        s->free_count--;      // TODO atomic

        return new;
    }
}

node *grab_next(store *s, size_t base) {
    size_t s_size = 2 * base;
    size_t idx = s->index; // atomic read

    if (idx + 1 >= s_size) return NULL;

    s->index = idx + 1; // atomic compare and swap || continue

    return s->nodes + idx;
}

store *find_store(dict *d, void *want, store **parent, int *dir) {
    if (parent) *parent = NULL;
    if (dir) *dir = 0;
    store *f = &(d->root);
    int root = 1;

    while (f && !address_in_store((uintptr_t)want, (uintptr_t)f, d->base, root)) {
        root = 0;
        if (parent) *parent = f;

        if ((uintptr_t)want < (uintptr_t)f) {
            if (dir) *dir = -1;
            f = f->left;
        }
        else {
            if (dir) *dir = 1;
            f = f->right;
        }
    }

    return f;
}

node *alloc_node(dict *d, void *key, node *root, node *parent) {
    assert(root);
    if (!parent) parent = root;
    node *new = NULL;

    while(1) {
        // The root node, which is always allocated, is available
        if (root->key = key) { // TODO Atomic swap from NULL
            root->val   = NULL;
            root->hash  = 0;
            root->left  = NULL;
            root->right = NULL;
            return root;
        }

        // find the correct free store
        store *f = find_store(d, parent, NULL, NULL);

        // Grab one from the correct store
        if (f) {
            new = grab_free(f);
            if (new) break;
        }

        // Grab one from any free list
        f = &(d->root);
        while (f) {
            new = grab_free(f);
            if (new) break;
            f = f->next; // atomic read
        }

        // Grab next one from current store
        new = grab_next(d->store, d->base);
        if (new) break;

        // Create a new store
        store *old = d->store; // atomic read
        size_t s_size = store_size(d->base, 0);

        // Only place where allocating a node can truly fail, out of memory.
        store *s = malloc(s_size);
        if (!s) return NULL;

        memset(s, 0, s_size);
        new = grab_next(s, d->base);
        s->next = old; // atomic set
        if (!(d->store = s)) { // atomic cmp+swap
            // Someone beat us to it.
            new = NULL;
            free(s);
            continue;
        }

        // Insert new store into the tree
        while(1) {
            store *pstore = NULL;
            int dir;
            store *f = find_store(d, s, &pstore, &dir);
            assert(!f);
            assert(pstore);
            assert(dir == 1 || dir == -1);
            if (dir == -1) {
                pstore->left = s; // atomic compare && break
            }
            else {
                pstore->right = s; // atomic compare && break;
            }
        }
    }

    memset(new, 0, sizeof(node));
    new->key = key; // TODO atomic
    return new;
}

void unalloc_node(dict *d, node *n) {
    if(is_root_node(n, &(d->root), d->base)) {
        n->key = NULL; // ATOMIC
        return;
    }

    store *s = find_store(d, n, NULL, NULL);
    assert(s);

    while(1) {
        node *p = s->free;
        n->key  = p; // Atomic set
        s->free = n; // Atomic swap or try again
    }

}

// Node locations
node *find_root_node(store *root_store, uint64_t hash);
node *find_node(node *root, uint64_t hash, void *key, node **parent);

// Node management
void *update_node(node *n, void *old, void *new); // Atomic swap, allow NULL
void *insert_node(node *nearest, node *new);      // Atomic insert, loop with a search+update on nearest
void *remove_node(node *n, node *parent);         // Note: Assert key set to NULL already

dict *dict_create(size_t base) {
    size_t sts = store_size(base, 1) - sizeof(store);
    size_t dsize = sizeof(dict) + sts;
    dict *dict = malloc(dsize);
    if (!dict) return NULL;
    memset(dict, 0, dsize);

    dict->base  = base;
    dict->store = &(dict->root);

    return dict;
}

void dict_free(dict *d);

void *dict_insert(dict *d, uint64_t hash, void *key, void *val) {
    node *new = NULL;

    node *root   = find_root_node(&(d->root), hash);
    node *parent = NULL;

    node *existing = NULL;
    void *ekey     = NULL;

    while(1) {
        existing = find_node(root, hash, key, &parent);
        ekey = existing->key;

        // If we got an existing one transaction fails, unless it is in the process of being deleted
        if (existing) {
            if (ekey) return ekey;
            continue; // Deletion in progress.
        }

        new = alloc_node(d, key, root, parent); // Optimistic
        if (!new) return NULL;

        //new->key = key; // already done
        new->val   = val;
        new->hash  = hash;
        new->left  = NULL;
        new->right = NULL;

        // Add it to parent
        if (hash <= parent->hash) {
            parent->left = new; // TODO atomic!
        }
        else {
            parent->right = new; // TODO atomic!
        }

        // Try again :-(
        if (new == root) {
            new = NULL;
        }
        else {
            unalloc_node(d, new);
        }
    }

    // Success
    return val;
}

*/
