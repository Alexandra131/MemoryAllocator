// SPDX-License-Identifier: BSD-3-Clause

#include "block_meta.h"
#include "osmem.h"
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define ALIGNMENT 8 // must be a power of 2
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define SIZE_T_SIZE (ALIGN(sizeof(size_t))) // header size
int contor;
int calloc_contor;
struct block_meta *heap_list;
struct block_meta *init_block(size_t size)
{
	if (size == 0)
		return NULL;

	size_t threshold;
	size_t threshold2 = 128 * 1024;

	if (calloc_contor == 1)
		threshold = getpagesize() - ALIGN(sizeof(struct block_meta));
	else
		threshold = 128 * 1024;

	size_t total_size = sizeof(struct block_meta) + size;
	struct block_meta *block;

	if (total_size > threshold) {
		block = (struct block_meta *)mmap(NULL, total_size, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (block == MAP_FAILED)
			return NULL;
		block->size = size;
		block->next = NULL;
		block->prev = NULL;
		block->status = STATUS_MAPPED;
		return block;
	}
	block = sbrk(threshold2);
	if (block == MAP_FAILED)
		return NULL;
	block->size = size;
	block->next = NULL;
	block->prev = NULL;
	block->status = STATUS_ALLOC;
	return block;
}

void coalesce(void)
{
	struct block_meta *current = heap_list;

	while (current != NULL && current->next != NULL) {
		if (current->status == STATUS_FREE
				&& current->next->status == STATUS_FREE) {
			current->size += current->next->size + sizeof(struct block_meta);
			current->next = current->next->next;
			if (current->next != NULL)
				current->next->prev = current;
		} else {
			current = current->next;
		}
	}
}

struct block_meta *find_best_fit(size_t size)
{
	coalesce();
	struct block_meta *cursor = heap_list;
	struct block_meta *cursor_prev = NULL;
	struct block_meta *best_fit_size = NULL;

	while (cursor != NULL) {
		if (cursor->status == STATUS_FREE && cursor->size >= size) {
			if (best_fit_size == NULL || ALIGN(cursor->size) < best_fit_size->size)
				best_fit_size = cursor;
		}
		cursor_prev = cursor;
		cursor = cursor->next;
	}
	if (best_fit_size == NULL && cursor_prev->status == STATUS_FREE) {
		sbrk(ALIGN(size - ALIGN(cursor_prev->size)));
		cursor_prev->size = ALIGN(size);
		coalesce();
		return cursor_prev;
	} else if (best_fit_size == NULL) {
		struct block_meta *block_return;

		block_return
				= (struct block_meta *)sbrk(ALIGN((size) + sizeof(struct block_meta)));
		block_return->size = ALIGN(size);
		block_return->next = NULL;
		block_return->prev = cursor_prev;
		block_return->status = STATUS_ALLOC;
		cursor_prev->next = block_return;
		coalesce();
		return block_return;
	}
	if (best_fit_size->size
		>= (8 + ALIGN(sizeof(struct block_meta)) + ALIGN(size))) {
		struct block_meta *free_space;

		free_space = (struct block_meta *)(ALIGN(
			(size_t)best_fit_size + ALIGN(size + sizeof(struct block_meta))));
		free_space->size = ALIGN(
			best_fit_size->size - sizeof(struct block_meta) - ALIGN(size));
		free_space->next = best_fit_size->next;
		free_space->prev = best_fit_size;
		best_fit_size->next = free_space;
		free_space->status = STATUS_FREE;
		best_fit_size->status = STATUS_ALLOC;
		best_fit_size->size = ALIGN(size);
		coalesce();
		return best_fit_size;
	}
	best_fit_size->status = STATUS_ALLOC;
	coalesce();
	return best_fit_size;
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	size_t threshold;

    if (calloc_contor == 1)
    threshold = getpagesize() - ALIGN(sizeof(struct block_meta));
    else
    threshold = 128 * 1024;

	size_t total_size = ALIGN(size) + sizeof(struct block_meta);

	struct block_meta *return_block;

	if (contor == 0) {
		heap_list = init_block(size);
		contor = 1;
		if (heap_list != NULL)
			return (char *)heap_list + sizeof(struct block_meta);
	}
	if (contor != 0) {
		if (size < threshold) {
			return_block = find_best_fit(size);
			return (char *)return_block + sizeof(struct block_meta);
		} else {
			return_block = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (return_block == MAP_FAILED)
				return NULL;
			return_block->size = ALIGN(size);
			return_block->next = NULL;
			return_block->prev = NULL;
			return_block->status = STATUS_MAPPED;
			return (char *)return_block + sizeof(struct block_meta);
		}
	}
	return NULL;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	struct block_meta *block_free = ((struct block_meta *)ptr) - 1;

	if (block_free->status == STATUS_MAPPED) {
		munmap(block_free, sizeof(struct block_meta) + block_free->size);
	} else if (block_free->status == STATUS_ALLOC) {
		block_free->status = STATUS_FREE;
		block_free->size = ALIGN(block_free->size);
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	calloc_contor = 1;

	if (nmemb == 0 || size == 0)
		return NULL;
	void *calloc_block = os_malloc(nmemb * size);

	if (calloc_block == NULL)
		return NULL;
	memset(calloc_block, 0, nmemb * size);
	calloc_contor = 0;
	return calloc_block;
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(ALIGN(size));
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	size_t *header = (size_t *)((char *)ptr - SIZE_T_SIZE);
	size_t old_size, new_size;

	old_size = *header & ~1L;
	new_size = ALIGN(size + SIZE_T_SIZE);

	void *newptr;

	if (old_size >= new_size)
		return ptr;
	newptr = os_malloc(ALIGN(size));
	memcpy(newptr, ptr, old_size - SIZE_T_SIZE);
	os_free(ptr);
	return newptr;

}
