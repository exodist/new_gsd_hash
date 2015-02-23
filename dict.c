#include "dict.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct node  node;
typedef struct store store;

struct node {
    size_t hash;

    void *key;
    void *val;

    node *left;
    node *right;
};

struct store {
    size_t free_count;

    store *next;
    node  *free;

    store *left;
    store *right;

    size_t index;
    node   nodes[]; // root ? 6 x base : 2 x base
};

struct dict {
    size_t base;
    store *store;
    store root;
    size_t free;
};

// store utils
inline size_t store_size(size_t base, int root);
inline int address_in_store(uintptr_t addr, uintptr_t s, size_t base);
node *grab_next(store *s, size_t base);
node *grab_free(store *s);
store *find_store(dict *d, void *want, store **parent, int *dir);

// Node allocation
node *alloc_node(dict *d, void *key, node *root, node *parent);
node *unalloc_node(dict *d, node *n);

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

inline int address_in_store(uintptr_t addr, uintptr_t s, size_t base) {
    uintptr_t end = s + store_size(base, 0);
    if (addr > end || addr < s) return 0;
    return 1;
}

node *grab_free(store *s) {
    while(1) {
        node *new = s->free;
        if (!new) return NULL;

        s->free = new->val; // TODO atomic || try again
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

    while (f && !address_in_store((uintptr_t)want, (uintptr_t)f, d->base)) {
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
        if (!root->key) {
            if (root->key = key) { // TODO Atomic
                return root;
            }
            continue;
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

    new->key = key; // TODO atomic
    return new;
}

node *unalloc_node(dict *d, node *n);

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

/* Update an existing node, return value of node
 * If node does not exist, return NULL
 * If value is not oldval, return current value
 * return newly set value
 */
void *dict_update(dict *d, uint64_t hash, void *key, void *oldval, void *newval);

/* Remove a node, return value of removed node
 * If node does nto exist return NULL
 * If value is not oldval fail and return node value
 * return value of removed node
 */
void *dict_remove(dict *d, uint64_t hash, void *key, void *oldval);

/* Get the value of a node, NULL if no such node
 */
void *dict_check(dict *d, uint64_t hash, void *key);

/* Set the value of a node, ignoring current value, returns value of node
 * If node cannot be inserted, return NULL (out of memory)
 * If value cannot be changed return old value
 * Return the newly set value.
 */
void *dict_set(dict *d, uint64_t hash, void *key, void *newval);
