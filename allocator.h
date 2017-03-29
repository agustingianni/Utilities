/*
 * allocator.h
 *
 *  Created on: Feb 11, 2016
 *      Author: anon
 */

#ifndef ALLOCATOR_H_
#define ALLOCATOR_H_

namespace os {

#include <sys/mman.h>

void *alloc_rwx_memory(size_t size) {
	auto tmp = mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC,
	MAP_ANON | MAP_PRIVATE, -1, 0);

	return tmp == MAP_FAILED ? nullptr : tmp;
}

}

namespace allocator {

#include <pthread.h>

class Lock;

class Mutex {
public:
	Mutex() {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
		pthread_mutex_init(&m_mutex, &attr);
	}

	~Mutex() {
		pthread_mutex_destroy(&m_mutex);
	}

private:
	friend class Lock;

	void lock() {
		pthread_mutex_lock(&m_mutex);
	}

	void unlock() {
		pthread_mutex_unlock(&m_mutex);
	}

	pthread_mutex_t m_mutex;
};

class Lock {
public:
	Lock(Mutex &mutex) :
			m_mutex(mutex) {
		m_mutex.lock();
	}

	~Lock() {
		m_mutex.unlock();
	}

private:
	Mutex &m_mutex;
};

// Default size of each SLAB is 16 mb.
class BumpAllocator {
public:
	BumpAllocator() :
			m_memory(0), m_used(0) {
	}

	void *allocate(size_t size) {
		Lock lock(m_mutex);

		if (!m_memory) {
			if (!init()) {
				return nullptr;
			}
		}

		if (fits(size)) {
			if (!init()) {
				return nullptr;
			}
		}

		auto tmp = m_memory;
		m_memory = static_cast<char *>(m_memory) + size;
		m_used += size;

		return tmp;
	}

private:
	bool init() {
		Lock lock(m_mutex);

		m_used = 0;
		m_memory = os::alloc_rwx_memory(BumpAllocator::SLAB_SIZE);
		if (m_memory == nullptr) {
			return false;
		}

		return true;
	}

	inline bool remaining() {
		return BumpAllocator::SLAB_SIZE - m_used;
	}

	inline bool fits(size_t size) {
		return size < remaining();
	}

	static const size_t SLAB_SIZE = 16777216;

	void *m_memory;
	size_t m_used;
	Mutex m_mutex;
};

}

#endif /* ALLOCATOR_H_ */
