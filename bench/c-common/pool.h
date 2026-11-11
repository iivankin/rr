/*
 * cpu scenario: a pool of POOLN threads that runs fnv_rounds off the
 * event loop. The loop submits a Job; a worker computes it, puts it on
 * the done list and writes the eventfd; the loop reads the eventfd (with
 * epoll or through the ring) and takes the whole done list at once.
 * Needs http.h first.
 */
#ifndef BENCH_POOL_H
#define BENCH_POOL_H

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

#define POOLN 4

typedef struct Job Job;
struct Job {
	Job *next;
	void *owner;            /* the connection */
	uint32_t n;
	uint64_t result;
};

static struct {
	pthread_mutex_t mu;
	pthread_cond_t cv;
	Job *head, **tail;      /* queued */
	pthread_mutex_t dmu;
	Job *done;              /* finished, LIFO */
	int efd;
	unsigned char *zero;    /* HASHBUF zeroes */
} pool;

static void *
pool_worker(void *arg)
{
	Job *j;
	uint64_t one;

	(void)arg;
	one = 1;
	for (;;) {
		pthread_mutex_lock(&pool.mu);
		while (!pool.head)
			pthread_cond_wait(&pool.cv, &pool.mu);
		j = pool.head;
		pool.head = j->next;
		if (!pool.head)
			pool.tail = &pool.head;
		pthread_mutex_unlock(&pool.mu);

		j->result = fnv_rounds(pool.zero, j->n);

		pthread_mutex_lock(&pool.dmu);
		j->next = pool.done;
		pool.done = j;
		pthread_mutex_unlock(&pool.dmu);
		while (write(pool.efd, &one, sizeof(one)) < 0 && errno == EINTR)
			;
	}
	return NULL;
}

/* efd_flags: EFD_NONBLOCK for epoll, 0 for a read through io_uring. */
static int
pool_start(int efd_flags)
{
	pthread_t t;
	int i;

	pool.zero = calloc(1, HASHBUF);
	if (!pool.zero)
		return -1;
	pool.efd = eventfd(0, EFD_CLOEXEC | efd_flags);
	if (pool.efd < 0)
		return -1;
	pthread_mutex_init(&pool.mu, NULL);
	pthread_cond_init(&pool.cv, NULL);
	pthread_mutex_init(&pool.dmu, NULL);
	pool.tail = &pool.head;
	for (i = 0; i < POOLN; i++) {
		if (pthread_create(&t, NULL, pool_worker, NULL))
			return -1;
		pthread_detach(t);
	}
	return pool.efd;
}

static void
pool_submit(Job *j)
{
	j->next = NULL;
	pthread_mutex_lock(&pool.mu);
	*pool.tail = j;
	pool.tail = &j->next;
	pthread_cond_signal(&pool.cv);
	pthread_mutex_unlock(&pool.mu);
}

/* Everything finished so far; call after the eventfd fired. */
static Job *
pool_take(void)
{
	Job *j;

	pthread_mutex_lock(&pool.dmu);
	j = pool.done;
	pool.done = NULL;
	pthread_mutex_unlock(&pool.dmu);
	return j;
}

#endif
