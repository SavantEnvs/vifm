/* libFuzzer harness for vifm's string trie (src/utils/trie.h).  Input: one byte (repeat count, 1..64)
 * followed by newline-separated keys.  Every key is repeated that many times, because libFuzzer inputs
 * are capped (Mayhem: 8192 bytes) while callers pass arbitrarily long strings to the trie (history
 * texts from vifminfo.json, paths).  Each key goes through trie_put()/trie_set() and must be found
 * in the trie and in a clone of it afterwards. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/utils/trie.h"

#define MAX_REPEAT 64

static char ** split_keys(const uint8_t data[], size_t size, size_t *nkeys);
static void check_found(trie_t *trie, const char key[]);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if(size == 0)
	{
		return -1;
	}

	size_t nkeys;
	char **keys = split_keys(data, size, &nkeys);
	if(keys == NULL)
	{
		return 0;
	}

	trie_t *trie = trie_create(/*free_func=*/NULL);
	size_t i;
	for(i = 0; trie != NULL && i < nkeys; ++i)
	{
		const int result = (i % 2 == 0) ? trie_put(trie, keys[i])
		                                : trie_set(trie, keys[i], keys[i]);
		if(result < 0)
		{
			/* Only out-of-memory is possible for a non-empty key. */
			break;
		}
		check_found(trie, keys[i]);
	}

	if(i == nkeys && trie != NULL)
	{
		/* Earlier keys must have survived later insertions. */
		trie_t *clone = trie_clone(trie);
		for(i = 0; i < nkeys; ++i)
		{
			check_found(trie, keys[i]);
			if(clone != NULL)
			{
				check_found(clone, keys[i]);
			}
		}
		trie_free(clone);
	}

	trie_free(trie);
	for(i = 0; i < nkeys; ++i)
	{
		free(keys[i]);
	}
	free(keys);
	return 0;
}

/* Splits the data after the repeat count into keys and repeats each one; keys that are empty C
 * strings are skipped as trie rejects them by contract.  Returns NULL on out-of-memory. */
static char **
split_keys(const uint8_t data[], size_t size, size_t *nkeys)
{
	const size_t repeat = 1 + data[0] % MAX_REPEAT;
	char **keys = calloc(size, sizeof(*keys));
	*nkeys = 0;
	if(keys == NULL)
	{
		return NULL;
	}

	size_t start = 1;
	while(start < size)
	{
		const uint8_t *nl = memchr(data + start, '\n', size - start);
		const size_t len = (nl != NULL ? (size_t)(nl - (data + start)) : size - start);
		if(len > 0 && data[start] != '\0')
		{
			char *key = malloc(len*repeat + 1);
			if(key == NULL)
			{
				break;
			}
			size_t r;
			for(r = 0; r < repeat; ++r)
			{
				memcpy(key + r*len, data + start, len);
			}
			key[len*repeat] = '\0';
			keys[(*nkeys)++] = key;
		}
		start += len + 1;
	}
	return keys;
}

static void
check_found(trie_t *trie, const char key[])
{
	void *found;
	if(trie_get(trie, key, &found) != 0)
	{
		abort();
	}
}
