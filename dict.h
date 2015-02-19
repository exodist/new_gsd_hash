#include <stdint.h>
#include <stdlib.h>

typedef struct set  set;
typedef struct dict dict;

// Free
void dict_free(dict *d);
void  set_free(set  *s);

// Create a new one
dict *dict_create(size_t base, uint64_t seed);
set   *set_create(size_t base, uint64_t seed);

/*
 * ALL operations are atomic unless otherwise noted, also completely thread
 * safe.
 */

/* Insert a new node, return value of node
 * If node already exists value of the node is returned
 * If node does not exist create it and return the newly set value (same as val)
 * If node cannot be created return NULL
 */
void *dict_insert(dict *d, uint64_t hash, void *key, void *val);

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
 * If value cannot be changed (can this happen?) return old value
 * Return the newly set value.
 */
void *dict_set(dict *d, uint64_t hash, void *key, void *newval);

/* Insert a key into the set
 * return 0  (false) if it fails
 * return 1  (true)  if it succeeds
 * return -1 (true)  if it is already set
 */
int set_insert(set *s, uint64_t hash, void *key);

/* Remove a key from the set
 * return 1  (true)  if the key was present and removed
 * return -1 (true)  if the key was not present
 * return 0  (false) if the key could not be removed
 */
int set_remove(set *s, uint64_t hash, void *key);

/* Check if a key is in a set
 * return 1 (true)  if the key is present
 * return 0 (false) if the key is not present
 */
int set_check(set *s, uint64_t hash, void *key);
