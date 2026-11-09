/* libFuzzer harness for vifm's string trie (src/utils/trie.h).  The input is a list of keys separated
 * by newlines.  Every key goes through trie_put()/trie_set(), is looked up in the trie and in a clone
 * of it, and must be found.  Keys are not length-limited: callers (e.g. history texts from
 * vifminfo.json, file paths) pass arbitrary strings. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/utils/trie.h"

static void check_found(trie_t *trie, const char key[]);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *input = malloc(size + 1);
	if(input == NULL)
	{
		return 0;
	}
	memcpy(input, data, size);
	input[size] = '\0';

	trie_t *trie = trie_create(/*free_func=*/NULL);
	if(trie == NULL)
	{
		free(input);
		return 0;
	}

	int use_set = 0;
	char *key, *next;
	for(key = input; key != NULL; key = next)
	{
		next = strchr(key, '\n');
		if(next != NULL)
		{
			*next++ = '\0';
		}

		/* An empty key is an error by trie's contract. */
		if(*key == '\0')
		{
			continue;
		}

		const int result = use_set ? trie_set(trie, key, key) : trie_put(trie, key);
		use_set = !use_set;
		if(result < 0)
		{
			/* Only out-of-memory is possible for a non-empty key. */
			trie_free(trie);
			free(input);
			return 0;
		}

		check_found(trie, key);
	}

	/* Re-read the whole input to check that earlier keys survived later insertions. */
	size_t len = size;
	char *copy = malloc(len + 1);
	if(copy != NULL)
	{
		memcpy(copy, data, len);
		copy[len] = '\0';

		trie_t *clone = trie_clone(trie);
		for(key = copy; key != NULL; key = next)
		{
			next = strchr(key, '\n');
			if(next != NULL)
			{
				*next++ = '\0';
			}
			if(*key != '\0')
			{
				check_found(trie, key);
				if(clone != NULL)
				{
					check_found(clone, key);
				}
			}
		}
		trie_free(clone);
		free(copy);
	}

	trie_free(trie);
	free(input);
	return 0;
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
