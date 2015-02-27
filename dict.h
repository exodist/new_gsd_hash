#include <stdint.h>
#include <stdlib.h>

typedef struct dict      dict;
typedef struct dict_iter dict_iter;

dict *dict_create(size_t base);
void  dict_free(dict *d);

dict_iter *dict_iter_create(dict *d);
void      *dict_iter_free(dict_iter *i);

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
 * If value cannot be changed return old value
 * Return the newly set value.
 */
void *dict_set(dict *d, uint64_t hash, void *key, void *newval);


// Iterate through all key/value pairs
// Note: Inserting nodes while iterating has undefined results, some may be
// seen, others may not be.
// _start functions reset the iterator
// _next get the next in sequence
// the order for the pairs returned is not defined.
size_t dict_iter_start(dict_iter *i, void **key, void **val);
size_t dict_iter_next (dict_iter *i, void **key, void **val);
void *dict_iter_start_key(dict_iter *i);
void *dict_iter_next_key (dict_iter *i);
void *dict_iter_start_val(dict_iter *i);
void *dict_iter_next_val (dict_iter *i);
